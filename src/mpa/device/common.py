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
import codecs
import grp
import json
import pickle
import pwd
import shutil
import socket
import struct
import threading
from asyncio import IncompleteReadError
from collections.abc import MutableMapping
from configparser import RawConfigParser
from enum import Enum
from functools import cache
from pathlib import Path
from typing import Any, Dict, List, Iterator, Mapping, Optional, Tuple, Union

# Third party imports
from sshpubkeys import AuthorizedKeysFile, SSHKey, InvalidKeyError  # type: ignore

# Local imports
import mpa.device.eeprom
from mpa.common.common import RESPONSE_FAILURE, RESPONSE_OK
from mpa.common.logger import Logger
from mpa.communication.common import (
    InvalidParameterError,
    InvalidPreconditionError,
    PLEASE_REPORT,
    SSHKeyManagementError,
    expect_empty_message,
)
from mpa.communication.inter_process_lock import InterProcessLock
from mpa.communication.message_parser import get_dict, get_str
from mpa.communication.process import run_command, run_command_unchecked
from mpa.communication.status_codes import DEVADMIN_GID, DEVREAD_GID
from mpa.config.common import CONFIG_DIR_ROOT
from mpa.config.configfiles import ConfigFiles

logger = Logger(__name__)
DEVICE_SET_CONFIG_LOCK = InterProcessLock(CONFIG_DIR_ROOT / "mgmtd/dev.set.config.lock", stale_lock_seconds=600)
SSH_SOCKET_PATH = Path('/run/mgmtd/ssh_daemon')
KERNEL_SOCKET_PATH = Path('/run/mgmtd/kernel_daemon')
SHADOW_SOCKET_PATH = Path('/run/mgmtd/shadow_daemon')
SOCKET_BUFFER_SIZE = 4096

# names of default config files
AZURE_CONFIG_JSON = "azure_config.json"
DEVICE_CONFIG_JSON = "device_config.json"
PROXY_CONFIG_JSON = "proxy_config.json"
SERIAL_CONFIG_JSON = "serial_config.json"
SSH_CONFIG_JSON = "ssh_config.json"
SMART_EMS_JSON = "smart_ems.json"
DATETIME_CONFIG_JSON = "datetime_config.json"
IOTEDGE_TOML = "iotedge.toml"
CONFIGURATION_FILE_HELP = "file with configuration data (default is '{}')"

# List of groups whose members, if they have it as their primary, can have their SSH keys modified
SSH_KEY_ALLOWED_PRIMARY_GROUPS = ['devadmin', 'devread']


# TODO switch to StrEnum when we move to Python 3.11
class SWUpdateScript(str, Enum):
    CHECK_OS_VERSION_PY = "check_os_version.py"
    SW_UPDATE_SCRIPT_SH = "sw-update-script.sh"


# Actions used ofver ssh socket (SSH_SOCKET_PATH)
# TODO switch to StrEnum when we move to Python 3.11
class SshAction(str, Enum):
    ADD = "add"
    SHOW = "show"
    REMOVE = "remove"
    GET_ALL = "getAll"
    SET_ALL = "setAll"


SOCKET_RETURN_TYPE = Dict[str, Any]

CONFIG_KEY_EDGE_CA_CERT = "cert"
CONFIG_KEY_EDGE_CA_PK = "pk"
CONFIG_KEY_TRUST_BUNDLE_CERT = "trust_bundle_cert"
CONFIG_KEY_DEVICE_ID_CERT = "identity_cert"
CONFIG_KEY_DEVICE_ID_PK = "identity_pk"
config_files: ConfigFiles = ConfigFiles()
# This file is used by users bash rc and by docker systemd configuration to set up proxy
PROXY_CONFIG_FILE = config_files.add("proxy.toml", "eg/proxy.toml")
MOTD_FILE = config_files.add("motd", "motd")
ISSUE_FILE = config_files.add("issue", "issue")
serial_ports_config = config_files.add("serial-ports", "eg/serial.conf")
TPM_PRESENCE_FILE = config_files.add("tpm-presence", "eg/tpm.conf")
VLANS_CONFIG = config_files.add("vlans-config", "eg/vlans.json", is_expected=False)
LOGIND_CONF = config_files.add("logind.conf",
                               "logind.conf.d/00-systemd-conf.conf",
                               config_dir_root=Path("/lib/systemd"))
SYSCTL_CONF = config_files.add("50-communication.conf", "sysctl.d/50-communication.conf")
SYSTEM_CONF = config_files.add("system.conf",
                               "system.conf.d/00-systemd-conf.conf",
                               config_dir_root=Path("/lib/systemd"))
# DNS configuration template lives under /etc/eg and can be activated
# by creating a symlink in /etc/systemd/resolved.conf.d/
RESOLVED_CONF = config_files.add("10-dns-resolved.conf",
                                 "eg/10-dns-resolved.conf")
LINK_TO_RESOLVED_CONF = config_files.add(
    "linked-10-dns-resolved.conf",
    "systemd/resolved.conf.d/10-dns-resolved.conf",
    is_expected=False,
)
# In systemd's login.conf file, default value for NAutoVTs is 6
# (means 6 virtual terminals will be enabled in local console)
LOGIND_DEFAULT_NAUTOVTS = 6
# In sysctl.conf, the default value for kernel.sysrq is 176
SYSCTL_SYSRQ_REBOOT_VALUE = '176'
SYSCTL_SYSRQ_IGNORE_VALUE = '0'
config_files.verify()


# TODO it would be good to
# * perform all write operations using new file and just swap files when
# and/or
# * think about some locking so while we modify the file nobody else will try to do it manually
class AuthorizedKeys:
    def __init__(self, username: str):
        self.username = username
        try:
            pwd.getpwnam(self.username)
        except KeyError:
            raise InvalidPreconditionError(f"User {self.username} does not exist")

        self.user_group = get_user_primary_group(username)
        if self.user_group is None:
            raise RuntimeError(f"User {self.username} should have assigned primary group")

        if self.user_group not in SSH_KEY_ALLOWED_PRIMARY_GROUPS:
            raise InvalidPreconditionError(f"Change of SSH keys for {self.username} is forbidden")

    def __writeable_key_file(self) -> Path:
        authorized_keys_file = self._get_user_ssh_directory() / ".ssh/authorized_keys"
        if not authorized_keys_file.exists():
            ssh_dir = authorized_keys_file.parent.absolute()
            if not ssh_dir.exists():
                ssh_dir.mkdir(parents=False, exist_ok=True)
                ssh_dir.chmod(0o744)
                if ssh_dir.owner() != self.username:
                    shutil.chown(ssh_dir, self.username, self.user_group)
            # Keep in sync with bbappend in yocto/meta-welotec/recipes-core/base-files/
            authorized_keys_file.touch(mode=0o644, exist_ok=True)
            if authorized_keys_file.owner() != self.username:
                shutil.chown(authorized_keys_file, self.username, self.user_group)
        return authorized_keys_file

    def __validate_key(self, key: str) -> None:
        ssh_key = SSHKey(key)
        try:
            ssh_key.parse()
        except InvalidKeyError as exc:
            raise InvalidParameterError(f"Received invalid ssh public key for user {self.username}. "
                                        f"Key value: {key}. Error: {str(exc)}")

    def read_ssh_keys(self) -> List[str]:
        keys = []
        authorized_keys_file = self._get_user_ssh_directory() / ".ssh/authorized_keys"

        if authorized_keys_file.exists():
            try:
                with authorized_keys_file.open("r") as fd:
                    key_file = AuthorizedKeysFile(fd, strict=False)
                for key in key_file.keys:
                    keys.append(key.keydata)
            except Exception as exc:
                # If something went wrong it is probably caused by user playing manually with authorized_keys file, so we
                # convert all exceptions blindly to SSHKeyManagementError which is "expected" error
                # TODO analyze what can actually go wrong and raise "expected" error only in such cases, where we are sure
                # it is not our fault
                logger.exception(exc)
                raise SSHKeyManagementError(f"For user {self.username}: {str(exc)}")
        else:
            logger.debug(f"{self.username} does not have authorized_keys file")
        return keys

    @staticmethod
    def get_all_keys() -> Tuple[Dict[str, List[str]], Dict[str, str]]:
        devadmin = get_all_users_with_primary_group("devadmin")
        devread = get_all_users_with_primary_group("devread")
        keys = {}
        user_status = {}
        for user in [*devadmin, *devread]:
            try:
                keys[user] = AuthorizedKeys(user).read_ssh_keys()
                user_status[user] = RESPONSE_OK
            except SSHKeyManagementError as key_error:
                user_status[user] = f"{RESPONSE_FAILURE} Issue with authorized keys file: {str(key_error)}"
            except Exception as exc:
                user_status[user] = f"{RESPONSE_FAILURE} Invalid state of device (please report to Welotec): {str(exc)}"
        return keys, user_status

    def delete_ssh_key(self, key_index: int) -> None:
        keys = self.read_ssh_keys()
        if key_index < 0 or len(keys) <= key_index:
            raise InvalidParameterError(f"There is no key with index {key_index} in authorized_keys file of user {self.username}")
        keys.pop(key_index)
        try:
            with self.__writeable_key_file().open("w") as key_file:
                for value in keys:
                    key_file.write(f"{value.strip()}\n")
        except Exception as exc:
            # If something went wrong it is probably caused by user playing manually with authorized_keys file, so we
            # convert all exceptions blindly to SSHKeyManagementError which is "expected" error
            # TODO analyze what can actually go wrong and raise "expected" error only in such cases, where we are sure
            # it is not our fault
            raise SSHKeyManagementError(f"For user {self.username}: {str(exc)}")

    # Return home path for selected user to access .ssh directory and modify authorized_keys
    def _get_user_ssh_directory(self) -> Path:
        return Path(f"~{self.username}").expanduser()

    def add_ssh_key(self, key: str) -> None:
        self.__validate_key(key)

        keys = self.read_ssh_keys()
        new_key = SSHKey(key)
        for value in keys:
            existing_key = SSHKey(value)
            # Please check description of add_publickey CLI command for updating the existing keys
            if existing_key.hash_sha512() == new_key.hash_sha512():
                raise InvalidPreconditionError("Key already present in authorized_keys")

        with self.__writeable_key_file().open(mode='a') as fd:
            fd.write(f"{key.strip()}\n")

    def replace_ssh_keys_of_user(self, new_keys: List[str]) -> None:
        for key_value in new_keys:
            self.__validate_key(key_value)
        self.__writeable_key_file().unlink()
        for key_value in new_keys:
            self.add_ssh_key(key_value)


class CaseSensitiveConfigParser(RawConfigParser):
    def optionxform(self, s: str) -> str:
        return s


class ConfctlParser(MutableMapping[str, Any]):
    def __init__(self, file_path: Path, default: Optional[Any] = None) -> None:
        self.file_path = file_path
        self.data: Dict[str, str] = {}
        self.default = default
        self.__read()

    def __read(self) -> None:
        with self.file_path.open('r') as file:
            for line in file:
                line = line.strip()
                if line.startswith('#') or line.startswith(';') or not line:
                    continue
                key, sep, value = line.partition('=')
                if sep:
                    self.data[key.strip()] = value.strip()

    def __getitem__(self, key: str) -> Optional[Any]:
        return self.data.get(key, self.default)

    def __setitem__(self, key: str, value: str) -> None:
        self.data[key] = value

    def __iter__(self) -> Iterator[str]:
        return iter(self.data)

    def __len__(self) -> int:
        return len(self.data)

    def __delitem__(self, key: str) -> None:
        del self.data[key]

    def write(self) -> None:
        content = '\n'.join(f'{key}={value}' for key, value in self.data.items())
        content += '\n'
        with self.file_path.open('w') as file:
            file.write(content)


def get_all_users_with_primary_group(group: str) -> List[str]:
    try:
        return [x.pw_name for x in pwd.getpwall() if x.pw_gid == grp.getgrnam(group).gr_gid]
    except KeyError:
        raise InvalidPreconditionError(f"Group {group} does not exists")


def get_user_primary_group(username: str) -> Union[str, None]:
    try:
        user_group_id = pwd.getpwnam(username).pw_gid
        for group in grp.getgrall():
            if user_group_id == group.gr_gid:
                return group.gr_name
        return None
    except KeyError:
        raise InvalidPreconditionError(f"User {username} does not exists")


def read_gea_serial_number(eeprom_file: Path) -> Optional[str]:
    try:
        eeprom_data = eeprom_file.read_bytes()
    except PermissionError as e:
        logger.exception(e)
        run_command_unchecked(f"pkexec chmod 660 {eeprom_file.resolve()}")
        run_command_unchecked(f"pkexec chown root:mgmtd {eeprom_file.resolve()}")
        eeprom_data = eeprom_file.read_bytes()

    serial_number = mpa.device.eeprom.get_serial_number(eeprom_data)
    if serial_number is not None:
        # serial number may contain unprintable characters
        serial_number = "".join(filter(str.isprintable, serial_number))

    return serial_number


@cache
def get_serial_number() -> str:
    DEVICE_SERIAL_NUMBER = "unknown_serial_number"
    try:
        # TODO We create /dev/eeprom symlink in gea devices, so its presence is indicator of gea
        # device, in long term we want plugin system for serial numbers (see MPA-1628)
        dev_eeprom = Path("/dev/eeprom")
        if dev_eeprom.exists():
            DEVICE_SERIAL_NUMBER = read_gea_serial_number(dev_eeprom) or DEVICE_SERIAL_NUMBER
        else:
            DEVICE_SERIAL_NUMBER = run_command("pkexec dmidecode -s system-serial-number").stdout.decode('utf-8').strip()
    except Exception as exc:
        if config_files.is_debug_mode_enabled():
            raise exc
        logger.exception(exc)
    return DEVICE_SERIAL_NUMBER


# Taken from https://stackoverflow.com/a/65627642
def read_exactly(sock: socket.socket, num_bytes: int) -> bytes:
    buf = bytearray(num_bytes)
    pos = 0
    while pos < num_bytes:
        n = sock.recv_into(memoryview(buf)[pos:])
        if n == 0:
            # recv returns any data available up to requested size
            # so if we get 0 it means that socket was in non-blocking mode and
            # there were no data, or socket was in blocking mode and received data
            # was smaller than we wanted
            raise IncompleteReadError(bytes(buf[:pos]), num_bytes)
        pos += n
    return bytes(buf)


def send_and_wait_for_response_on_socket(data: bytearray, socket_path: str = str(SSH_SOCKET_PATH)) -> SOCKET_RETURN_TYPE:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as mgmtd_socket:
        # TODO how should we handle this more gracefully?
        # reading/sending data from/to the closed socket may result in BrokenPipeError: [Errno 32] Broken pipe
        # so the timeout was increased from 1 to 2 seconds
        mgmtd_socket.settimeout(2)
        mgmtd_socket.connect(socket_path)
        mgmtd_socket.sendall(struct.pack(">I", len(data)))
        if len(data):
            mgmtd_socket.sendall(data)
        response_size = struct.unpack(">I", read_exactly(mgmtd_socket, 4))[0]
        response_payload = read_exactly(mgmtd_socket, response_size)
        return parse_response_from_socket(response_payload)


def parse_response_from_socket(response: bytes) -> SOCKET_RETURN_TYPE:
    decoded_message: Dict[str, Any] = json.loads(response)
    status = get_str(decoded_message, "status")
    if status == RESPONSE_OK:
        return decoded_message
    elif status == RESPONSE_FAILURE:
        base64_exception = get_str(decoded_message, "exception").encode()
        exc = pickle.loads(codecs.decode(base64_exception, "base64"))
        raise exc
    else:
        raise RuntimeError(f"Recevied unkown status: {status}")


def check_if_admin_has_public_ssh_key() -> bool:
    payload = {"username": "admin", "action": SshAction.SHOW}
    message = bytearray(json.dumps(payload), encoding="UTF-8")
    ssh_keys = get_dict(send_and_wait_for_response_on_socket(message), "keys")
    return bool(len(ssh_keys["admin"]))


def get_serial_devices() -> Mapping[str, str]:
    try:
        lines = serial_ports_config.read_text().strip().splitlines()
    except FileNotFoundError:
        logger.warning(f"The file '{serial_ports_config}' does not exist.")
        return {}

    if lines == ["MACHINE_WITHOUT_SERIALS"]:
        return {}
    if "MACHINE_WITHOUT_SERIALS" in lines:
        raise RuntimeError(
            "The serial.conf file is broken as it contains information about "
            f"serial devices while there shouldn't be serial devices {lines}"
        )
    if len(lines) == 0:
        raise RuntimeError(f"The machine is misconfigured as not having any serial devices. {PLEASE_REPORT}")

    return dict(line.split("=") for line in lines)


def get_all_users(*groups: int) -> List[Dict[str, str]]:
    group_names = {}
    for group in groups:
        try:
            group_names[group] = grp.getgrgid(group).gr_name
        except KeyError as e:
            group_names[group] = "unknown"
            if config_files.is_debug_mode_enabled():
                raise e

    users = []
    for u in filter(lambda u: u.pw_gid in groups, pwd.getpwall()):
        user = {"name": u.pw_name, "type": group_names[u.pw_gid]}
        users.append(user)

    return users


def get_user_list() -> Dict[str, List[Dict[str, str]]]:
    users = get_all_users(DEVADMIN_GID, DEVREAD_GID)
    return {"users": users}


def reboot() -> None:
    logger.info("REBOOT: reboot()")
    run_command_unchecked("pkexec /usr/sbin/eg_reboot")


def reboot_device(message: bytes) -> None:
    logger.info("REBOOT: reboot_device()")
    expect_empty_message(message, "reboot_device")
    delayed_reboot = threading.Timer(5, reboot)
    delayed_reboot.start()
