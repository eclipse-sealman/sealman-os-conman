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
import threading
import json
import functools
import sys
from pathlib import Path

# Local imports
import mpa.communication.topics as topics
from mpa.common.common import RESPONSE_OK
from mpa.common.common import RESPONSE_FAILURE
from mpa.common.logger import Logger
from mpa.common.killer_thread import KillerThread
from mpa.communication.client import Client  # import to get Client as type for mypy
from mpa.communication.common import InvalidPayloadError
from mpa.communication.daemon_transaction import DaemonTransaction
from mpa.communication.message_parser import get_optional_bool
from mpa.config.common import CONFIG_DIR_ROOT, CONFIG_FORMAT_VERSION_TO_ASSUME_FOR_UNVERSIONED_CONFIG
from mpa.device.common import DEVICE_SET_CONFIG_LOCK
from typing import Any, Dict, List, Mapping, Optional, Union

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")

DEVICE_BACKUP_CONFIG = Path(f"{CONFIG_DIR_ROOT}/mgmtd/device_config.back")

# TODO Get better name
set_config_handlers = {
    "azure": topics.azure.set_config,
    "date_time": topics.dev.datetime.set_config,
    "dns": topics.net.dns.set_config,
    "docker": topics.docker.set_config,
    "dockerdns": topics.docker.dns.set_config,     # We allow old configs to work
    "firewall": topics.net.filter.set_config,
    "logrotate": topics.dev.logrotate.set_config,
    "network": topics.net.set_config,
    "dhcp_server": topics.net.dhcp_server.set_config,
    "ovpn": topics.net.ovpn.set_config,
    "proxy_servers": topics.dev.proxy.set_config,
    "serial": topics.dev.serial.set_config,
    "smartems": topics.smart_ems.set_config,
    "sshconfig": topics.dev.ssh.set_config,
    "motd": topics.dev.motd.set_config,
    "issue": topics.dev.issue.set_config,
    "user_password_hashes": topics.dev.user.password_hash.set_config,
    "static_routing": topics.net.routing.set_config,
    "local_console": topics.dev.local_console.set_config,
    "webgui": topics.webgui.set_config,
    "vlans": topics.net.vlan.set_config,
}


class SetConfig:
    """
    This class contains method wich allows to send config from one source (eg. backup file or SmartEMS request) to specific
    daemon. Class supports transaction and auto rollback to previous, working configuration.
    """
    def __init__(self, client: Client, logger: Any) -> None:
        self.__client = client
        self.__logger = logger
        self.__rolled_back = False
        self.__results: Dict[str, Union[bytes, str, None]] = dict()
        self.__statuses: Dict[str, Union[bool, None]] = dict()
        self.errors: List[str] = list()
        self.__configs: Dict[str, Dict[str, Any]] = {}
        self.__deamon_transaction = DaemonTransaction("", self.__client)
        self.__logger.debug("Created SetConfig instance")

    def __add_error_message(self, target: str, message: str) -> None:
        error_message = f"{target}: {message}"
        self.__client.send("dev.set_config.rt", error_message)  # send partial response to CLI
        self.errors.append(error_message)

    def __callback(self, event: threading.Event, target: str, topic: str, message: Union[bytes, str]) -> Optional[bool]:
        # TODO Question to reviewers:
        # I don't want to all event.set() before we finish processing status decoding...
        # Shall we create context manager to call event.set() or shall we use finally?
        # Or maybe you have some better idea how to solve it?
        # It think that with context manager would be overkill here but I also don't like finally...
        try:
            logger.debug(f"Got response from topic: {topic} target: {target} message: {message!r}")
            self.__results.update({topic: message})
            # TODO all of query handlers have similar structure (checking for message being str or not to see if we have
            # real response) This handler is additionally quite similar to communication.common.exiting_print_message
            # (but it does not print anything, but stores data in __statuses and sends messages to CLI We shall think
            # about extracting those commonalties somehow
            if isinstance(message, str):  # forwarder said: no response expected
                self.__add_error_message(target, f"UNKNOWN STATUS: {message}")
                return False  # returning False means we don't want to wait for that probably missing message
            try:
                response = json.loads(message)
            except json.decoder.JSONDecodeError as exc:
                self.__statuses.update({topic: False})
                self.__add_error_message(target, f"{RESPONSE_FAILURE} Invalid format of response: {message!r}")
                logger.exception(exc)
                return None
            if isinstance(response, str):
                if response.startswith(RESPONSE_OK):
                    self.__statuses.update({topic: True})
                    self.__client.send("dev.set_config.rt", f"{target}: {response}")
                else:
                    self.__statuses.update({topic: False})
                    self.__add_error_message(target, response)
            else:
                self.__statuses.update({topic: False})
                self.__add_error_message(target, f"{RESPONSE_FAILURE} Invalid response format: {message!r}")
        finally:
            event.set()
        return None

    def __execute(self) -> None:
        self.__logger.debug(f"{self.__configs}")
        for target in self.__configs:
            self.__logger.debug(f"{target}")
            self.__statuses[target] = None
            self.__configs[target]["function"]()

    def __save_config(self, event: threading.Event, message: bytes) -> None:
        with DEVICE_BACKUP_CONFIG.open(mode="w") as config_backup_file:
            json.dump(json.loads(message), config_backup_file)
        event.set()
        return None

    def get_results(self) -> Mapping[str, Union[bytes, str, None]]:
        # We use Mapping for mypy to rant when somebody tries to modify results
        return self.__results

    def prepare_backup_config(self) -> None:
        event = threading.Event()
        callback_with_event = functools.partial(self.__save_config, event)
        self.__client.query(topics.dev.get_config, "", callback_with_event)
        event.wait()

    def __add(self, topic: str, target: str, message: Dict[str, Any]) -> None:
        event = threading.Event()
        message.update({"ask_for_affirmation": False})  # We want only global affrim
        callback_with_event = functools.partial(self.__callback, event, target, topic)
        function_to_call = functools.partial(self.__client.query, target, message, callback_with_event)
        self.__configs.update({topic: {"event_object": event,
                                       "function": function_to_call}})

    def execute_and_wait(self) -> None:
        self.__execute()
        for target in self.__configs:
            self.__configs[target]["event_object"].wait()
        self.__configs.clear()

    # TODO Check following scenario:
    # 1. Apply new config (via smartems) which will trigger crash or hang of one of mgmtd daemons after partial config application
    # 2. smartems.py receives error response and calls rollback_config
    # 3. rollback_config now needs to deal with daemon which crashed or is hanged --- open question is if backup file
    #    will be removed (it shall not, as crashed/hanged daemon cannot apply it)
    def rollback_config(self) -> None:
        # This artificial error will allow to see which errors were before and which after rollback
        self.errors.append("Rolling back changes!!!")
        self.__client.send("dev.set_config.rt", "Rolling back changes!!!")
        try:
            content = DEVICE_BACKUP_CONFIG.read_text()
            backup_config = json.loads(content)
            self.set_config_file(backup_config, continue_despite_errors=True)
            self.execute_and_wait()
            self.__rolled_back = True
        except json.JSONDecodeError:
            logger.error(f"device backup config contains invalid json: '{content}'")
            self.__client.send(f"device backup config contains invalid json and could not be applied: '{content}'")
        finally:
            self.remove_backup()

    def __final_handler(self, event: threading.Event, rollback: bool) -> None:
        if rollback:
            background_thread = KillerThread(target=self.rollback_config)
            background_thread.start()
        else:
            self.remove_backup()
        event.set()

    def remove_backup(self) -> None:
        DEVICE_BACKUP_CONFIG.unlink(missing_ok=True)

    def confirm_config(self, from_part: bytes, message_id: bytes, *, warn_about_ignored_keys: bool = False) -> threading.Event:
        event = threading.Event()
        final_handler = functools.partial(self.__final_handler, event)

        self.__deamon_transaction.start("dev.set_config", final_handler, from_part, message_id)
        # We are cheating a bit --- everything was already done before we started transaction, so we can immediately set
        # response
        if len(self.errors) == 0 and not warn_about_ignored_keys:
            question = None
            error_state = "without errors"
        else:
            if len(self.errors):
                question = ("There were some errors detected"
                            f"{' and ignored section of config' if warn_about_ignored_keys else ''}. "
                            "Do you want to keep this potentially invalid new config?")
                error_state = "despite errors"
            else:
                question = "There were ignored sections of config. Do you want to keep this potentially partial config?"
                error_state = "despite ignored sections"
        response = f"{RESPONSE_OK} Confirmation received. New configuration has been applied {error_state}."
        self.__deamon_transaction.set_response(response, question=question)
        return event

    def set_config_file(self, config: Dict[str, Any], *, continue_despite_errors: bool = False) -> list[str]:
        self.__configs.clear()
        self.__results.clear()
        ignored_keys: list[str] = list()
        self.config_format_version = config.pop('config_format_version', CONFIG_FORMAT_VERSION_TO_ASSUME_FOR_UNVERSIONED_CONFIG)
        meta_options = config.pop('meta_options', {})
        ignore_unknown_config_sections = get_optional_bool(meta_options, "ignore_unknown_config_sections")
        if self.config_format_version == CONFIG_FORMAT_VERSION_TO_ASSUME_FOR_UNVERSIONED_CONFIG:
            if "updater" in config and 'smartems' not in config:
                config['smartems'] = config.pop('updater')

        # Check if both dhcp_server and network are present to enable merging
        merge_network_and_dhcp_server_config = "dhcp_server" in config and "network" in config

        for key in config:
            if key in set_config_handlers:
                try:
                    if key == "dhcp_server" and merge_network_and_dhcp_server_config:
                        continue

                    # Common parameters for all cases
                    params = {
                        key: config[key],
                        "config_format_version": self.config_format_version,
                        "meta_options": meta_options
                    }

                    # Add dhcp_server to params only for network key when merging
                    if key == "network" and merge_network_and_dhcp_server_config:
                        params["dhcp_server"] = config["dhcp_server"]

                    self.__add(key, set_config_handlers[key], params)
                except Exception as exc:
                    if continue_despite_errors:
                        self.__client.send("dev.set_config.rt", f"Setting {key}, ignored exception: {exc}")
                        logger.warning(f"Continuing despite error while adding {key} "
                                       f"(probably during restoring partially broken backup): {exc}")
                        ignored_keys.append(key)
                    else:
                        logger.warning(f"Rejecting config because failed to add {key}: {exc}")
                        self.__client.send("dev.set_config.rt",
                                           f"Unexpected error when adding {key}, no changes shall be apllied")
                        raise
            elif ignore_unknown_config_sections or continue_despite_errors:
                ignored_keys.append(key)
                msg = f"Ignored unknown config key: {key}"
                self.__client.send("dev.set_config.rt", msg)
                self.__logger.info(msg)
            else:
                raise InvalidPayloadError(f"Unknown config section {key}")
        return ignored_keys


def check_if_backup_config_exists(client: Client) -> None:
    """
    This function runs on daemon initialization. The purpose of this function is
    to make sure that configuration was properly applied to the device and there is
    no backup file present on device. In case that backup file is present,
    function assumes that previous attempt to set config was unsucesfully
    (eg. due to power failure) and tries to restore configuration from backup.

    This function must be called after client is initilizated and all other
    deamons are up and running.
    """
    if DEVICE_BACKUP_CONFIG.exists():
        logger.info("Found backup config file, start process to restore previous configuration")

        def background_task() -> None:
            with DEVICE_SET_CONFIG_LOCK.transaction("Global lock to restore backup device config"):
                try:
                    content = DEVICE_BACKUP_CONFIG.read_text()
                    backup_config = json.loads(content)
                    setconfig = SetConfig(client, logger)
                    # We have lock, so we can remove backup immediately,
                    # so if we hang we will not try to apply same backup file again
                    setconfig.remove_backup()
                except json.JSONDecodeError:
                    logger.error(f"device backup config contains invalid json: '{content}'")
                    return

                setconfig.set_config_file(backup_config, continue_despite_errors=True)
                setconfig.execute_and_wait()

        background = KillerThread(target=background_task, args=())
        background.start()
