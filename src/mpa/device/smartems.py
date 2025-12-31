#
# Copyright (c) 2025 Contributors to the Eclipse Foundation.
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License, Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
#
# Standard imports
import copy
import functools
import json
import sys
from enum import Enum
from os import statvfs, getpid
from pathlib import Path
from threading import Event
from typing import Any, Callable, Dict, Mapping, MutableMapping, Optional, TypeVar, Union
from urllib.parse import urlparse

# Third party imports
import libarchive  # type: ignore
import libconf  # type: ignore
import requests
from tenacity import retry, stop_after_delay, wait_exponential, retry_if_exception_type
import toml

# Local imports
import mpa.communication.topics as topics
from mpa.common.common import RESPONSE_FAILURE
from mpa.common.common import RESPONSE_OK
from mpa.communication.common import expect_empty_message
from mpa.common.logger import Logger
from mpa.common.killer_thread import KillerThread
from mpa.communication.common import read_file_content
from mpa.communication.common import InvalidParameterError, \
                                 SmartEMSError, SWUpdateError, InvalidVersionError, InvalidImageFeaturesError
from mpa.communication.client import Client  # import to get Client as type for mypy
from mpa.communication.common import get_current_root_partition
from mpa.communication.common import get_os_release_info
from mpa.communication.common import ConflictingOperationInProgessError
from mpa.communication.message_parser import get_optional_str
from mpa.communication.inter_process_lock import InterProcessLock
from mpa.communication.status_codes import CERTIFICATE
from mpa.config.common import SYSTEMD_ROOT
from mpa.config.configfiles import ConfigFiles
from mpa.device.common import DEVICE_SET_CONFIG_LOCK, PROXY_CONFIG_FILE, SWUpdateScript
from mpa.device.device_config import SetConfig
from mpa.device.tpm import get_data_from_tpm_module
from mpa.device.firmware import run_swupdate
from mpa.device.timer import update_timer
from mpa.device.common import get_serial_number, reboot_device

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")

DEVICE_SERIAL_NUMBER = get_serial_number()

CHECK_LOGS = "Please check device logs for more information."

T = TypeVar('T')  # pylint: disable=invalid-name


def call_with_proxy(requests_call: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    if PROXY_CONFIG_FILE.exists():
        config = toml.loads(PROXY_CONFIG_FILE.read_text())
        proxies = {'http': get_optional_str(config, 'http_proxy'),
                   'https': get_optional_str(config, 'https_proxy')}
        if "timeout" not in kwargs:
            kwargs["timeout"] = 31  # requests suggests timeout to be a bit more than multiple of 3
        return requests_call(*args, **kwargs, proxies=proxies)
    return requests_call(*args, **kwargs)


class SmartEMS:
    class SmartEMSCommands(Enum):
        UPDATE_CONFIG = "update_config"
        GET_CONFIG = "get_config"
        UPDATE_FIRMWARE = "update_firmware"

    FIRMWARE_DOWNLOAD_PATH = "/tmp/"

    config_files = ConfigFiles()
    SMARTEMS_CONFIG_FILE = config_files.add("smartems", "smartems/config.cfg")
    SMARTEMS_CERT_PATH = config_files.add("smart_ems_cert", "smartems/custom.pem", is_expected=False)
    SMARTEMS_TRANSACTION_ID = config_files.add("transaction_id", "eg/smart_ems_transaction_id", is_expected=False)
    SMARTEMS_PREPARED_RESPONSE = config_files.add("prepared_response", "eg/response_to_smart_ems", is_expected=False)
    SMART_EMS_TRANSACTION_LOCK_FILE = config_files.add("lock_file", "eg/smart_ems_transaction_lock", is_expected=False)
    HARDWARE_VERSION_FILE = config_files.add("hw-version", "hw-version")
    SOFTWARE_VERSION_FILE = config_files.add("sw-version", "sw-version")
    SMART_EMS_TIMER = config_files.add("smart_ems_timer", "system/smartems.timer", config_dir_root=SYSTEMD_ROOT)
    config_files.verify()
    LOCK = InterProcessLock(SMART_EMS_TRANSACTION_LOCK_FILE, stale_lock_seconds=900)

    HW_VERSION = read_file_content(HARDWARE_VERSION_FILE).split(" ")[1].upper()
    SW_VERSION = read_file_content(SOFTWARE_VERSION_FILE).strip()

    EMS_REQUEST_TEMPLATE: Dict[str, Any] = {
        'registrationId': '{reg_id}',
        'endorsementKey': '{endorsement_key}',
        'hardwareVersion': HW_VERSION,
        'firmwareVersion': SW_VERSION,
        'serialNumber': DEVICE_SERIAL_NUMBER
    }

    EMS_TIMER_TEMPLATE = """[Unit]
Description=Smart EMS Update timer
Documentation=

[Timer]
OnCalendar=daily
OnBootSec=180s
AccuracySec=1
OnUnitActiveSec={interval}s
Persistent=true

[Install]
WantedBy=timers.target
"""

    def __init__(self, client: Client) -> None:
        self._client = client
        self.message_from_smartems: Dict[str, Any] = {}
        self.next_command: Optional[Callable[[], None]] = None
        self.skip_ssl_verification: bool = False

        # "edgegatewayvcc" may be not present in config after update
        self.get_endpoint()

    # TODO: switch to ACL approach instead of chmod (this function was created before we introduced ACL's
    def __update_timer(self, interval: int) -> None:
        update_timer(
            interval=interval,
            timer=self.SMART_EMS_TIMER,
            timer_template=self.EMS_TIMER_TEMPLATE
        )

    def _load_smartems_config(self) -> Any:
        try:
            return json.loads(self.SMARTEMS_CONFIG_FILE.read_text())
        except json.JSONDecodeError:
            logger.error("Invalid SmartEMS config detected; replacing with empty config")
            return {}

    def get_endpoint(self) -> str:
        content: Dict[str, Any] = self._load_smartems_config()
        old_endpoint = "/api/edgegateway/configuration"
        new_endpoint = "/api/edgegatewayvcc/configuration"
        try:
            endpoint: str = new_endpoint if content["edgegatewayvcc"] else old_endpoint
            return endpoint
        except KeyError:
            content["edgegatewayvcc"] = False
            self.SMARTEMS_CONFIG_FILE.write_text(json.dumps(content))
            return old_endpoint

    def check_if_url_exists(self, url: str) -> str:
        response = call_with_proxy(requests.head, url, allow_redirects=True, verify=self.get_cert_status())

        logger.debug(f"Status for {url}: {response.status_code}")

        if response.status_code == 404:
            raise SmartEMSError(f"System was unable to connect to: {url}")

        logger.info(f"New URL to connect: {response.url}")

        for resp in response.history:
            logger.info(f"Request was redirected to: {resp.url} with code: {resp.status_code}")

        return response.url

    def manage_cert(self, message: bytes) -> Optional[str]:
        user_data = json.loads(message)
        if user_data["action"] == CERTIFICATE.ADD.value:
            if self.SMARTEMS_CERT_PATH.exists():
                logger.info("Custom SmartEMS certificate will be overwritten")
            with open(self.SMARTEMS_CERT_PATH, 'w') as file:
                file.write(user_data['cert_content'])
            return f"{RESPONSE_OK} Certificate saved"
        if user_data["action"] == CERTIFICATE.DELETE.value:
            if self.SMARTEMS_CERT_PATH.exists():
                self.SMARTEMS_CERT_PATH.unlink(missing_ok=False)
                return f"{RESPONSE_OK} Custom certificate removed"
            return f"{RESPONSE_OK} No file to remove"
        if user_data["action"] == CERTIFICATE.SHOW.value:
            try:
                with open(self.SMARTEMS_CERT_PATH, 'r') as file:
                    cert_data = file.read()
                    return f"{RESPONSE_OK} {cert_data}"
            except OSError:
                return f"{RESPONSE_OK} No custom certificate"
        return f"{RESPONSE_FAILURE} Unknown action"

    def read_smart_ems_config(self) -> str:
        return read_file_content(self.SMARTEMS_CONFIG_FILE)

    def __prepare_minimal_message_to_smartems(self) -> MutableMapping[str, Any]:
        message_to_smartems = self.EMS_REQUEST_TEMPLATE.copy()
        reg_id, endorsement_key = get_data_from_tpm_module()
        message_to_smartems['registrationId'] = reg_id
        message_to_smartems['endorsementKey'] = endorsement_key
        if 'commandTransactionId' in self.message_from_smartems:
            message_to_smartems['commandTransactionId'] = self.message_from_smartems.pop('commandTransactionId')
        if 'commandName' in self.message_from_smartems:
            message_to_smartems['commandName'] = self.message_from_smartems.pop('commandName')
        return message_to_smartems

    def __add_error_params_to_message_to_smartems(self, message_to_smartems: MutableMapping[str, Any],
                                                  category: str, *, description: str) -> None:
        message_to_smartems['commandStatus'] = 'error'
        message_to_smartems['commandStatusErrorCategory'] = category
        message_to_smartems['commandStatusErrorPid'] = getpid()
        message_to_smartems['commandStatusErrorMessage'] = description
        logger.error(f"Peparing error for smartems: {description}")
        self._client.send("smart_ems.rt", f"ERROR: {description}")

    def __add_success_params_to_message_to_smartems(self, message_to_smartems: MutableMapping[str, Any],
                                                    description: str) -> None:
        message_to_smartems['commandStatus'] = 'success'
        logger.info(f"Peparing success for smartems: {description}")
        self._client.send("smart_ems.rt", description)

    def __prepare_success_response_to_smartems(self, description: str) -> MutableMapping[str, Any]:
        message_to_smartems = self.__prepare_minimal_message_to_smartems()
        self.__add_success_params_to_message_to_smartems(message_to_smartems, description)
        return message_to_smartems

    def __prepare_error_response_to_smartems(self, category: str, *, description: str) -> MutableMapping[str, Any]:
        message_to_smartems = self.__prepare_minimal_message_to_smartems()
        self.__add_error_params_to_message_to_smartems(message_to_smartems, category, description=description)
        return message_to_smartems

    def download_firmware(self, url: str, local_path: Path, content_length: int, chunk_size: int = 8192, **kwargs: Any) -> None:
        """
        Download a file with resume capability and retry logic.
        Args:
            url (str): URL of the file to download
            local_path (Path): Local path where file will be saved
            content_length (int): Size of the file to download
            chunk_size (int): Size of chunks to download in bytes
        """

        filesize = local_path.stat().st_size if local_path.exists() else 0

        @retry(
            stop=stop_after_delay(1800),  # stop retrying after 30 minutes
            wait=wait_exponential(min=2, max=60),  # exponential backoff: 2s, 4s, ..., 60s
            retry=retry_if_exception_type(requests.exceptions.ConnectionError),
            before_sleep=lambda retry_state: self._client.send(
                "smart_ems.rt",
                f"Connection lost. Retrying download... Attempt {retry_state.attempt_number}",
            ),
            reraise=True,
        )
        def _download() -> None:
            nonlocal filesize
            with call_with_proxy(
                requests.get, url,
                stream=True,
                headers={"Range": f"bytes={filesize}-"},
                **kwargs
            ) as response:
                response.raise_for_status()
                mode = "ab" if filesize else "wb"
                with local_path.open(mode) as f:
                    for chunk in response.iter_content(chunk_size=chunk_size):
                        filesize += f.write(chunk)
                        if filesize % 100000 == 0:
                            msg = f"Download progress: {filesize / content_length:>7.2%}"
                            self._client.send("smart_ems.rt", msg)
                            logger.info(msg)

            assert local_path.stat().st_size == content_length, "Downloaded firmware size and expected size mismatch"

        try:
            _download()
        except Exception as e:
            error_description = f"System was not able to download firmware. {CHECK_LOGS}"
            data = self.__prepare_error_response_to_smartems("downloaderror", description=error_description)
            self.__send_http_request_to_smartems(data)
            logger.error(f"Download failed: {str(e)}")
            raise

    # TODO do we want to use this function directly in check_smart_ems but put
    # instead check_smart_ems to background?
    def _exec_command_update_firmware(self) -> None:
        """
        This function is intended to run in separate thread.
        In case of any error it will not throw any exception. All errors are reported by logging only.

        Args:
            url (str): URL to SmartEMS endpoint
        """
        logger.info("Begin --- Firmware download")
        assert self.message_from_smartems['commandName'] == self.SmartEMSCommands.UPDATE_FIRMWARE.value
        self._client.send("smart_ems.rt", "Starting to download the firmware to /tmp directory")

        url: str = self.message_from_smartems.pop("firmwareUrl")
        logger.info(f"Downloading new firmware: {url}")
        ems_config = json.loads(self.read_smart_ems_config())
        # it may not be present in a config
        self.skip_ssl_verification = ems_config.get('skip_ssl_verification') or False
        update_filename = url.split('/')[-1]
        # TODO can we do something like below to avoid duplication of args creation for head and get?
        # http_request_args = {'url': url,
        #                     'verify': self.get_cert_status(),
        #                     'auth': requests.auth.HTTPBasicAuth(ems_config['username'], ems_config['password'])}
        # response = call_with_proxy(requests.head, **http_request_args)
        auth = requests.auth.HTTPBasicAuth(ems_config['username'], ems_config['password'])
        verify = self.get_cert_status()
        response = call_with_proxy(requests.head, url, verify=verify, auth=auth)
        temp_disk_stats = statvfs("/tmp")
        tmp_free_in_bytes = temp_disk_stats.f_frsize * temp_disk_stats.f_bfree
        firmwaresize = int(response.headers['content-length'])
        if firmwaresize > tmp_free_in_bytes:
            data = self.__prepare_error_response_to_smartems('nospace',
                                                             description="Not enough space on /tmp to download firmware.")
            self.__send_http_request_to_smartems(data)
            return

        update_file_path = Path(f"{self.FIRMWARE_DOWNLOAD_PATH}/{update_filename}")
        self.download_firmware(
            url,
            update_file_path,
            firmwaresize,
            verify=verify,
            auth=auth
        )
        logger.info("End --- Firmware download")
        self._client.send("smart_ems.rt", "Firmware download finished, starting installation")
        with libarchive.SeekableArchive(str(update_file_path)) as swupdate_file:
            config = libconf.loads(swupdate_file.read("sw-description").decode())

        version = None
        with_gui_support = None
        error_message = ""

        for script in config.software.scripts:
            match script.filename:
                case SWUpdateScript.CHECK_OS_VERSION_PY if with_gui_support is None:
                    with_gui_support = script.data == "WITH_GUI_SUPPORT"
                case SWUpdateScript.SW_UPDATE_SCRIPT_SH if version is None:
                    version = script.data
                case SWUpdateScript.CHECK_OS_VERSION_PY | SWUpdateScript.SW_UPDATE_SCRIPT_SH:
                    error_message += f"\nThere is more than one {script.filename} script."
                    break
                case _:
                    if self.config_files.is_debug_mode_enabled():
                        error_message += f"\nUnkown script: {script.filename}."
                        break

        if version is None or with_gui_support is None:
            error_message += "\nThe version and/or gui support fields are missing."

        if len(error_message) > 0:
            data = self.__prepare_error_response_to_smartems(
                "badfirmware",
                description=f"SWUpdate file is incorrect.{error_message}")
            self.__send_http_request_to_smartems(data)
            logger.info("SmartEMS was not able to update device")
            return

        self.__update_transaction_on_disk("requested_version", version)
        if with_gui_support:
            self.__update_transaction_on_disk("requested_gui_support", "TRUE")
        try:
            run_swupdate(update_file_path)
            self._client.send("smart_ems.rt", "New firmware installed, the device will reboot soon")
            reboot_device(b"")  # runs in a different thread after 5 seconds
            # we want to be sure python exits with statement and releases lock
            # sys.exit will wait for other threads to finish, so we will exit the
            # with statement first and release lock and after that reboot will happen
            sys.exit(0)
        except (SWUpdateError, InvalidVersionError, InvalidImageFeaturesError) as error:
            update_file_path.unlink(missing_ok=False)  # remove bad firmware file
            data = self.__prepare_error_response_to_smartems("badfirmware",
                                                             description=str(error))
            self.__send_http_request_to_smartems(data)
            logger.info("SmartEMS was not able to update device")
            return

    def get_cert_status(self) -> Union[bool, str]:
        """Check SmartEMS certificate status

        Returns:
            Union[bool, str]: Returns True if requests should verify SSL certificate, False otherwise. If custom self signed cert
                            is uploaded to the device returns path to it,
                            requests should use this certificate to check connections.
        """
        verify: Union[bool, str] = True
        if self.config_files.is_debug_mode_enabled() or self.skip_ssl_verification:
            verify = False
        elif self.SMARTEMS_CERT_PATH.exists():
            verify = str(self.SMARTEMS_CERT_PATH)
        return verify

    def _exec_command_set_config(self) -> None:
        self._client.send("smart_ems.rt", "Received config from SMART EMS - applying")
        assert self.message_from_smartems['commandName'] == self.SmartEMSCommands.UPDATE_CONFIG.value
        try:
            with DEVICE_SET_CONFIG_LOCK.transaction("Global lock for device settings"):
                try:
                    config = self.message_from_smartems.pop('config')
                    if "meta_options" not in config:
                        config["meta_options"] = {}
                    meta_options = config["meta_options"]
                    if "ignore_unknown_config_sections" not in meta_options:
                        meta_options["ignore_unknown_config_sections"] = True
                    if "ignore_superflous_config_entries" not in meta_options:
                        meta_options["ignore_superflous_config_entries"] = True
                    setconfig = SetConfig(self._client, logger)
                    setconfig.prepare_backup_config()
                    ignored_sections = setconfig.set_config_file(config)
                except Exception as exc:
                    error_description = ("Config was not applied because failure while parsing it. "
                                         f"Exception was {exc}")
                    data = self.__prepare_error_response_to_smartems("setconfigerror", description=error_description)
                else:
                    setconfig.execute_and_wait()
                    if len(setconfig.errors):
                        # TODO see todo in SetConfig.rollback_config()
                        self._client.send("smart_ems.rt", "ERROR: New config setting failed, reverting...")
                        setconfig.rollback_config()
                        error_description = ("Config was reverted due to errors \n"
                                             "Following errors were returned: \n")
                        for error in setconfig.errors:
                            error_description += error + "\n"
                        data = self.__prepare_error_response_to_smartems("setconfigerror", description=error_description)
                    else:
                        setconfig.remove_backup()
                        if len(ignored_sections):
                            ignored_sections_description = " with following sections ignored: {ignored_sections}"
                        else:
                            ignored_sections_description = ""
                        success_message = f"Config applied correctly{ignored_sections_description}"
                        data = self.__prepare_success_response_to_smartems(success_message)
        # ConflictingOperationInProgessError will happen in case we cannot start DEVICE_SET_CONFIG_LOCK.transaction
        # We allow other exceptions to escape (leaving next_command unclean) intentionally, as those exceptions shall
        # not happen, and we will clean up next_command anyway later
        except ConflictingOperationInProgessError as exc:
            data = self.__prepare_error_response_to_smartems('invalidprecondition', description=str(exc))
        self.__send_http_request_to_smartems(data)

    def _exec_command_get_config(self) -> None:
        self._client.send("smart_ems.rt", "Preparing config to be sent to Smart EMS")
        # _exec_command_get_config is called in thread (as part of e.g. check_smart_ems) which
        # process series of http message exchanges with smart ems and executes Smart EMS commands
        # one by one. Getting config is a bit special --- it requires the main thread to process few
        # other messages before it receives the config which can be sent back to Smart EMS, and only
        # after sending that config we can continue in Smart EMS thread with processig of following
        # commands. Hence callback (executed in main thread) uses event to singal Smart EMS command
        # processing thread that it can continue work.

        def get_config_callback(self: SmartEMS, event: Event, message: bytes) -> None:
            logger.info("get_config_callback inside response_with_config")
            config = json.loads(message)  # load json before preparing response, in case it throws
            data = self.__prepare_success_response_to_smartems("Sending config to Smart EMS")
            data['config'] = config
            self.__send_http_request_to_smartems(data)
            event.set()

        event = Event()
        callback_with_event = functools.partial(get_config_callback, self, event)
        self._client.query(topics.dev.get_config, "", callback_with_event)
        event.wait()

    def __write_transaction_to_disk(self, response_from_sems: Mapping[str, Any]) -> None:
        self.SMARTEMS_TRANSACTION_ID.write_text(json.dumps({'commandTransactionId': response_from_sems['commandTransactionId'],
                                                            'commandName': response_from_sems['commandName'],
                                                            'partition': get_current_root_partition(),
                                                            'sw_version': self.SW_VERSION,
                                                            'install_timestamp': get_os_release_info()['INSTALL_TIMESTAMP'],
                                                            'build_id': get_os_release_info()['BUILD_ID']}))

    def __update_transaction_on_disk(self, key: str, value: Any) -> None:
        transaction_text = self.SMARTEMS_TRANSACTION_ID.read_text()
        transaction = json.loads(transaction_text)
        transaction.update({key: value})
        self.SMARTEMS_TRANSACTION_ID.write_text(json.dumps(transaction))

    def __extract_http_errors_from_response(self, status_400_response: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            errors_children = status_400_response["errors"]["children"]
        except KeyError:
            errors_children = {}
        errors: Dict[str, Any] = {}
        for child, child_value in errors_children.items():
            if "errors" in child_value:
                child_errors = copy.copy(child_value["errors"])
                logger.info(f"Child {child} contains following errors: ")
                for error in child_errors:
                    logger.info(f"{error}")
                errors.update({child: child_errors})
        return errors

# TODO: Refactor that to command queue
    def __send_http_request_to_smartems(self, data: Mapping[str, Any]) -> None:
        if len(self.message_from_smartems):
            logger.warning(f"Message from smart ems not empty when sending new request: {self.message_from_smartems}")
        ems_config = json.loads(self.read_smart_ems_config())
        # it may not be present in a config
        self.skip_ssl_verification = ems_config.get('skip_ssl_verification') or False
        url_path = urlparse(ems_config['url'])  # Remove all '/' character occurrence at the end of the URL
        url = self.check_if_url_exists(f"{url_path.scheme}://{url_path.netloc}{self.get_endpoint()}")
        logger.debug(f"Sending message to Smart EMS: {data}")
        response = call_with_proxy(requests.post, url, json=data, verify=self.get_cert_status(),
                                   auth=requests.auth.HTTPBasicAuth(ems_config['username'], ems_config['password']),
                                   allow_redirects=True)
        logger.info(f"Received response from Smart EMS: {response.__dict__}")
        self.SMARTEMS_TRANSACTION_ID.unlink(missing_ok=True)

        SMART_EMS_COMMANDS = {
            self.SmartEMSCommands.UPDATE_CONFIG.value: self._exec_command_set_config,
            self.SmartEMSCommands.GET_CONFIG.value: self._exec_command_get_config,
            self.SmartEMSCommands.UPDATE_FIRMWARE.value: self._exec_command_update_firmware
        }

        if response.status_code == 200:
            response_from_sems = response.json()
            logger.debug(f"{response_from_sems}")
            if "error" in response_from_sems:
                logger.error(f"Received error from Smart EMS: {response_from_sems['error']} ")
                raise SmartEMSError(response_from_sems['error'])
            if "commandName" in response_from_sems:
                if "commandTransactionId" not in response_from_sems:
                    raise SmartEMSError(f"Missing 'commandTransactionId' in: {response_from_sems}")
                commandName = response_from_sems['commandName']
                if commandName not in SMART_EMS_COMMANDS:
                    raise SmartEMSError(f"SmartEMS sent unknown command: {response_from_sems}")
                self.__write_transaction_to_disk(response_from_sems)
                self.next_command = SMART_EMS_COMMANDS[response_from_sems['commandName']]
                self.message_from_smartems = response_from_sems
            else:
                if self.next_command is None:
                    self._client.send("smart_ems.rt", "Nothing requested by Smart EMS")
                else:
                    self._client.send("smart_ems.rt", "Nothing more requested by Smart EMS")
                    self.next_command = None
        elif response.status_code == 400:
            try:
                status_400_response = response.json()
            except Exception as exc:
                logger.info(f"Error during JSON parse: {exc}")
                raise SmartEMSError(exc)
            errors = self.__extract_http_errors_from_response(status_400_response)
            raise SmartEMSError(f"Smart EMS was unable to process the request, following errors were discovered: {errors}")
        elif response.status_code == 401:
            raise SmartEMSError("Unauthorized, please check your credentials.")
        elif response.status_code == 404:
            raise SmartEMSError("Endpoint not found, please check URL.")
        else:
            raise SmartEMSError(f"SmartEMS returns {response.status_code}")

    def check_smart_ems(self, message: bytes) -> None:
        '''
        This is blocking call to SmartEMS. It shall probably  be run in separate thread, especially if same process
        shall be processing other messages while waiting for end of SmartEMS communication sequence, which may take
        considerable amount of time in case of network slowness.
        '''
        expect_empty_message(message, "check_smart_ems()")
        with self.LOCK.transaction("Normal check for managment commands from SmartEMS"):
            if self.SMARTEMS_TRANSACTION_ID.exists():
                if self.SMARTEMS_PREPARED_RESPONSE.exists():
                    logger.error("Both pepared response and transaction id exists in filesystem, "
                                 f"ignoring pepared response '{self.SMARTEMS_PREPARED_RESPONSE.read_text()}'")
                    self.SMARTEMS_PREPARED_RESPONSE.unlink()
                request_to_ems = self.__prepare_smartems_request_from_disk_stored_transaction_without_reboot()
            elif self.SMARTEMS_PREPARED_RESPONSE.exists():
                try:
                    content = self.SMARTEMS_PREPARED_RESPONSE.read_text()
                    request_to_ems = json.loads(content)
                except json.JSONDecodeError:
                    error_description = f'Prepared smartems response is not a valid JSON: "{content}"'
                    request_to_ems = self.__prepare_error_response_to_smartems('generalerror', description=error_description)
            elif self.next_command is not None:
                error_description = 'Processing of past Smart EMS command sequence was not properly terminated.'
                request_to_ems = self.__prepare_error_response_to_smartems('abruptedcommand', description=error_description)
            else:
                request_to_ems = self.__prepare_minimal_message_to_smartems()
            try:
                self.__send_http_request_to_smartems(request_to_ems)
            except Exception:
                if self.SMARTEMS_PREPARED_RESPONSE.exists():
                    logger.error(f"Failed sending prepared response '{self.SMARTEMS_PREPARED_RESPONSE.read_text()}'")
                raise
            finally:
                self.SMARTEMS_PREPARED_RESPONSE.unlink(missing_ok=True)
            while self.next_command is not None:
                self.next_command()

    def set_ems_config(self, message: bytes) -> str:
        config = json.loads(message)['smartems']

        for key in ['username', 'password', 'url']:
            if key not in config:
                raise InvalidParameterError(f"Missing {key}")

        if "pollingInterval" in config:
            val = config["pollingInterval"]
            logger.info(f"pollingInterval is {val}")
            if val < 10:
                logger.info(f"pollingInterval is {val} and it is too low")
                raise InvalidParameterError(f"The value for polling interval is too low: {val}s. The minimum is 10s.")
            self.__update_timer(config['pollingInterval'])

        if "certificate" in config:
            if config['certificate'] != "":
                with open(self.SMARTEMS_CERT_PATH, 'w') as file:
                    file.write(config['certificate'])

        if "edgegatewayvcc" not in config:
            content: Dict[str, Any] = self._load_smartems_config()
            config["edgegatewayvcc"] = content.get("edgegatewayvcc", False)

        with open(self.SMARTEMS_CONFIG_FILE, "w") as cfg_file:
            cfg_file.write(json.dumps(config))

        return f"{RESPONSE_OK} Smart EMS config successfuly updated"

    def get_ems_config(self, message: bytes) -> Mapping[str, Any]:
        expect_empty_message(message, "get_ems_config()")
        config = self._load_smartems_config()
        if self.SMARTEMS_CERT_PATH.exists():
            with open(self.SMARTEMS_CERT_PATH, 'r') as file:
                cert_data = file.read()
        else:
            cert_data = ""
        config.update({"certificate": cert_data})
        output = {'smartems': config}
        return output

    def __prepare_smartems_request_from_disk_stored_transaction_common(self) -> MutableMapping[str, MutableMapping[str, Any]]:
        transaction_text = self.SMARTEMS_TRANSACTION_ID.read_text()
        try:
            transaction = json.loads(transaction_text)
            request_to_ems = self.__prepare_minimal_message_to_smartems()
            request_to_ems['commandTransactionId'] = transaction['commandTransactionId']
            request_to_ems['commandName'] = transaction['commandName']
            request_to_ems['commandStatusErrorPid'] = getpid()
            return {"request": request_to_ems, "transaction": transaction}
        finally:
            # Even if request preparation fails we need to unlink the file to avoid loop of failed preparations, but we
            # do it only if read_text succeeded (i.e. file existed in first line of this function)
            self.SMARTEMS_TRANSACTION_ID.unlink(missing_ok=True)

    def __prepare_smartems_request_from_disk_stored_transaction_without_reboot(self) -> MutableMapping[str, Any]:
        request_to_ems = self.__prepare_smartems_request_from_disk_stored_transaction_common()["request"]
        request_to_ems['commandStatusErrorMessage'] = f'Command execution failed. {CHECK_LOGS}'
        request_to_ems['commandStatusErrorCategory'] = 'generalerror'
        request_to_ems['commandStatus'] = 'error'
        return request_to_ems

    def __optional_features_match(self, transaction: Mapping[str, Any], os_release_info: Mapping[str, Any]) -> bool:
        requested_gui_support = (get_optional_str(transaction, "requested_gui_support") == "TRUE")
        present_gui_support = (get_optional_str(os_release_info, "WITH_GUI_SUPPORT") == '"TRUE"')
        return requested_gui_support == present_gui_support

    def __prepare_smartems_request_from_disk_stored_transaction_after_reboot(self) -> MutableMapping[str, Any]:
        request_and_transaction = self.__prepare_smartems_request_from_disk_stored_transaction_common()
        request_to_ems = request_and_transaction["request"]
        transaction = request_and_transaction["transaction"]
        if request_to_ems['commandName'] == self.SmartEMSCommands.UPDATE_FIRMWARE.value:
            error_description = 'System update failed.'
            if transaction['partition'] != get_current_root_partition():
                if 'requested_version' in transaction:
                    if transaction['requested_version'] == self.SW_VERSION:
                        os_release_info = get_os_release_info()
                        if self.__optional_features_match(transaction, os_release_info):
                            if transaction['install_timestamp'] != get_os_release_info()['INSTALL_TIMESTAMP']:
                                self.__add_success_params_to_message_to_smartems(request_to_ems,
                                                                                 "Successfuly booted from new firmware")
                                return request_to_ems
                            else:
                                error_description += f'System booted from old firmware. {CHECK_LOGS}'
                        else:
                            error_description += f'System booted with wrong optional image feature list. {CHECK_LOGS}'
                    else:
                        error_description += f"System booted with wrong software version. Expected: \
                                {transaction['requested_version']}, got: {self.SW_VERSION} {CHECK_LOGS}"
                else:
                    if transaction['sw_version'] != self.SW_VERSION:
                        self.__add_success_params_to_message_to_smartems(request_to_ems, "Successfuly booted from new firmware")
                        return request_to_ems
                    error_description += f'Requested version unknown, actual version unchanged. {CHECK_LOGS}'
            else:
                error_description += f'System booted from unchanged partition. {CHECK_LOGS}'
            self.__add_error_params_to_message_to_smartems(request_to_ems, 'systemupdatefailure', description=error_description)
        else:
            self.__add_error_params_to_message_to_smartems(request_to_ems, 'generalerror',
                                                           description=f'Command execution failed.  {CHECK_LOGS}')
        return request_to_ems

    def check_if_smartems_transaction_in_progress(self) -> None:
        """
        This function runs on daemon initialization. The purpose of this function is to check for any existing SmartEMS
        transaction in progress. If system finds any pending transaction it will check it type and send proper response
        to SmartEMS. Communication with SmartEMS is performed in background (so normal message processing, of e.g. CLI
        messages, is possible even if there are network/other delays to SmartEMS).

        This function must be called after _client is initilizated and all others deamons are up and running.
        """
        def background_task() -> None:
            try:
                if self.SMARTEMS_TRANSACTION_ID.exists():
                    with self.LOCK.transaction("Finish transaction after restart"):
                        request_to_ems = self.__prepare_smartems_request_from_disk_stored_transaction_after_reboot()
                        self.SMARTEMS_PREPARED_RESPONSE.write_text(json.dumps(request_to_ems))
                        self.__send_http_request_to_smartems(request_to_ems)
                        self.SMARTEMS_PREPARED_RESPONSE.unlink()
                    while self.next_command is not None:
                        self.next_command()
            except Exception as exc:
                logger.error("Execption caught in background_task of check_if_smartems_transaction_in_progress")
                logger.exception(exc)
        background_thread = KillerThread(target=background_task)
        background_thread.start()
