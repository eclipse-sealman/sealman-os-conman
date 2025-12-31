#!/usr/bin/env python3
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
"""
Daemon responsible for whole device configuration.
"""
from __future__ import annotations

# Standard imports
import argparse
import json
import toml
import pwd
import shutil
import re
import sys
import configparser

from pathlib import Path
from shlex import quote
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Tuple, Union, Callable

# Local imports
import mpa.communication.topics as topics
import mpa.device.date_time as date_time
from mpa.common.common import RESPONSE_OK
from mpa.common.common import RESPONSE_FAILURE
from mpa.common.common import empty_message_wrapper
from mpa.communication import client as com_client
from mpa.communication.client import background
from mpa.communication.client import convert_exception_to_message_failure_status
from mpa.communication.client import guarded
from mpa.communication.client import sync
from mpa.communication.client import RESPONSE_SUFFIX
from mpa.communication.common import InvalidPreconditionError, InvalidParameterError, InvalidPayloadError, SetSerialError
from mpa.communication.common import SSHKeyManagementError
from mpa.communication.common import TransactionRolledBackError
from mpa.communication.common import expect_empty_message
from mpa.communication.common import read_file_content
from mpa.communication.message_parser import get_bool, \
                                             get_dict, \
                                             get_enum_str, \
                                             get_int, \
                                             get_optional_bool, \
                                             get_optional_dict, \
                                             get_optional_int, \
                                             get_optional_str, \
                                             get_str, \
                                             get_str_with_default
from mpa.communication.status_codes import ADD_USER, REMOVE_USER, SHOW_USERS, \
                                       ADMIN_GROUP, USER_GROUP, \
                                       ADMIN_SYSTEM_GROUP, USER_SYSTEM_GROUP, \
                                       SUCCESS, HOUR, DAY, WEEK, MONTH
from mpa.communication.process import run_command
from mpa.communication.process import run_command_unchecked
from mpa.common.logger import Logger
from mpa.common.killer_thread import KillerThread
from mpa.config.common import CONFIG_FORMAT_VERSION
from mpa.device.azure import Azure
from mpa.device.tpm import get_data_from_tpm_module
from mpa.device.common import DEVICE_SET_CONFIG_LOCK
from mpa.device.common import SshAction
from mpa.device.common import SSH_KEY_ALLOWED_PRIMARY_GROUPS
from mpa.device.common import get_user_primary_group, get_user_list
from mpa.device.common import PROXY_CONFIG_FILE
from mpa.device.common import MOTD_FILE
from mpa.device.common import ISSUE_FILE
from mpa.config.configfiles import ConfigFiles
from mpa.device.common import CaseSensitiveConfigParser
from mpa.device.common import send_and_wait_for_response_on_socket
from mpa.device.common import check_if_admin_has_public_ssh_key
from mpa.device.common import get_serial_number, reboot_device
from mpa.device.common import KERNEL_SOCKET_PATH, SHADOW_SOCKET_PATH
from mpa.device.common import get_serial_devices
from mpa.device.common import LOGIND_CONF
from mpa.device.common import LOGIND_DEFAULT_NAUTOVTS
from mpa.device.common import SYSTEM_CONF
from mpa.device.common import SYSCTL_CONF
from mpa.device.common import SYSCTL_SYSRQ_REBOOT_VALUE
from mpa.device.common import SYSCTL_SYSRQ_IGNORE_VALUE
from mpa.device.common import ConfctlParser
from mpa.device.device_config import SetConfig, check_if_backup_config_exists
from mpa.device.smartems import SmartEMS

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")

config_files = ConfigFiles()
logrotate_config_file = config_files.add("logrotate", "logrotate.d/eg")
logrotate_global_config_file = config_files.add("logrotated", "logrotate.conf")
smartems_config_file = config_files.add("smartems", "smartems/config.cfg")
serial_ports_config = config_files.add("serial-ports", "eg/serial.conf")
hardware_version_file = config_files.add("hw-version", "hw-version")
software_version_file = config_files.add("sw-version", "sw-version")
SSH_AUTH_CONFIG = config_files.add("ssh_auth_config", "ssh/mgmtd/auth_config")
SSH_MAXSESSIONS = config_files.add("ssh_maxsessions", "ssh/mgmtd/maxsessions")
SSH_MAXSTARTUPS = config_files.add("ssh_maxstartups", "ssh/mgmtd/maxstartups")
PASSWD_FILE = config_files.add("passwd", "passwd")
CERT_STORE_PATH = config_files.add("ca-certificates_dir", "ca-certificates/", config_dir_root=Path("/usr/local/share/"))
LOGIN_TIMEOUT_CONFIG_FILE = config_files.add("tmout.sh", "eg/tmout.sh", is_expected=False)
config_files.add("eg_config_dir", "eg/")
config_files.verify()

HW_VERSION = read_file_content(hardware_version_file)
SW_VERSION = read_file_content(software_version_file)

logrotate_template = """
/var/log/*log {{
    rotate {rotate}
    {period}
    compress
    delaycompress
    missingok
    notifempty
    maxsize {size}M
    minsize 1
    nocreate
    postrotate
        kill -HUP $(systemctl show --property MainPID --value syslog)
    endscript
  }}
"""

GROUP_DATA = {ADMIN_GROUP: (ADMIN_SYSTEM_GROUP, Path("/home/admins")),
              USER_GROUP: (USER_SYSTEM_GROUP, Path("/home/ro_users"))}

SSH_CONFIG_SCRIPT = "/usr/sbin/sshauth_config"
SSH_AUTH_TEMPLATE = """PasswordAuthentication {pass_auth}
PubkeyAuthentication {key_auth}
"""
azure = Azure()


class GetConfigData:
    def __init__(self) -> None:
        self.config: MutableMapping[str, Any] = dict()
        self.active_requests: List[Tuple[bytes, bytes, bool]] = list()

    def respond(self, response: Any = None) -> None:
        if response is None:
            response = self.config
        for request in self.active_requests:
            _client.respond(
                f"{topics.dev.get_config_with_privates if request[2] else topics.dev.get_config}{RESPONSE_SUFFIX}",
                response,
                request[0],
                request[1]
            )
        self.active_requests = list()


get_config_data = GetConfigData()
serial_devices = get_serial_devices()


def tpm_get(message: bytes) -> Mapping[str, Any]:
    expect_empty_message(message, "tpm_get()")
    config: Dict[str, Any] = dict()
    config["registration_id"], config["endorsement_key"] = get_data_from_tpm_module()
    return config


def serial_read() -> Mapping[str, Any]:
    config: MutableMapping[str, Any] = {}
    output = {'serial': config}
    for name, device in serial_devices.items():
        config[name] = {}
        is_active = run_command_unchecked(f"systemctl is-active  --quiet serial-getty@{device}.service").returncode
        is_enabled_result = run_command_unchecked(f"systemctl is-enabled serial-getty@{device}.service")
        is_enabled = False
        if is_enabled_result.returncode == SUCCESS:
            if is_enabled_result.stdout.decode('ascii').strip() != "enabled-runtime":
                is_enabled = True
        config[name]['console_output'] = {"at_startup": is_enabled}
        config[name]['console_output'].update({"currently":  is_active == SUCCESS})
    return output


def get_serial(message: bytes) -> Mapping[str, Any]:
    expect_empty_message(message, "get_serial()")
    return serial_read()


def get_config_step_store(config_part: str, message: Union[str, bytes]) -> Optional[bool]:
    if isinstance(message, str):
        get_config_data.config[config_part] = message
        return False
    get_config_data.config.update(json.loads(message))
    return None


def get_config_step_store_sub(config_part: str, config_subpart: str, message: Union[str, bytes]) -> Optional[bool]:
    if config_part not in get_config_data.config:
        get_config_data.config[config_part] = {}
    if isinstance(message, str):
        get_config_data.config[config_part][config_subpart] = message
        return False
    get_config_data.config[config_part].update(json.loads(message))
    return None


def get_config_step_final(config_part: str) -> com_client.QueryHandlerCallable:
    def final_handler(message: Union[str, bytes]) -> Optional[bool]:
        try:
            return get_config_step_store(config_part, message)
        finally:
            get_config_data.respond()
    return final_handler


def get_config_step_trivial(config_part: str,
                            next_message_topic: str,
                            next_handler: com_client.QueryHandlerCallable) -> com_client.QueryHandlerCallable:
    def trivial_step_handler(message: Union[str, bytes]) -> Optional[bool]:
        _client.query(next_message_topic, "", next_handler)
        return get_config_step_store(config_part, message)
    return trivial_step_handler


def get_config_step_subconfig(config_part: str,
                              config_subpart: str,
                              next_message_topic: str,
                              next_handler: com_client.QueryHandlerCallable) -> com_client.QueryHandlerCallable:
    def subconfig_step_handler(message: Union[str, bytes]) -> Optional[bool]:
        _client.query(next_message_topic, "", next_handler)
        return get_config_step_store_sub(config_part, config_subpart, message)
    return subconfig_step_handler


def get_config_step_init(*, with_privates: bool) -> com_client.RespondingHandlerCallable:
    def handler(message: bytes, from_part: bytes, message_id: bytes) -> com_client.Async:
        expect_empty_message(message, "get_config_step_init()")
        get_config_data.active_requests.append((from_part, message_id, with_privates))
        if len(get_config_data.active_requests) == 1:
            try:
                get_config_data.config = azure.read_config(with_privates)
                get_config_data.config.update({"config_format_version": CONFIG_FORMAT_VERSION})
                if len(serial_devices):
                    get_config_data.config.update(serial_read())
                get_config_data.config.update(logrotate_get_config())
                get_config_data.config.update(get_ssh_config())
                get_config_data.config.update(proxy_config_read())
                get_config_data.config.update(motd_get_config())
                get_config_data.config.update(issue_get_config())
                if with_privates:
                    get_config_data.config.update(user_password_hash_get())
                get_config_data.config.update(get_local_console_config())
                get_config_data.config.update(date_time.read_config())
                gcst = get_config_step_trivial
                gcss = get_config_step_subconfig
                gcsf = get_config_step_final
                # This is unfortuantely a bit convoluted --- first we give the
                # message name, then handler, and typical gcst/gcsf handler gets as
                # first param config part which shall be created from the
                # received response. After creating this config part gcst
                # handler will send next message, and process it with next
                # handler, hence for easier reading we break typical indentation
                # rules, so we have message and corresponding config part in same line.
                _client.query(topics.webgui.get_config, "", gcst("webgui",
                              topics.net.get_config, gcst("network",                             # noqa: E128
                              topics.net.filter.get_config, gcst("firewall",                     # noqa: E128
                              topics.net.ovpn.get_config, gcst("ovpn",                           # noqa: E128
                              topics.webgui.get_config, gcst("webgui",                           # noqa: E128
                              topics.docker.dns.get_config, gcss("docker", "dockerdns",          # noqa: E128
                              topics.docker.params.get_config, gcss("docker", "params",          # noqa: E128
                              topics.docker.compose.get_config, gcss("docker", "compose_files",  # noqa: E128
                              topics.smart_ems.get_config, gcsf("smartems"))))))))))              # noqa: E128
            except:  # noqa: E722 we are doing trivial cleanup here, so it is ok to catch everything
                get_config_data.active_requests.pop()
                raise
        return com_client.Async()
    return handler


def toggle_serial(device: str, mode: Mapping[str, Any]) -> None:
    service = f"serial-getty@{device}.service"
    invalid_key_value = ""
    if len(mode) < 1:
        raise InvalidPayloadError("No information about what to do with console output")
    if len(mode) > 2:
        raise InvalidPayloadError("To many entries in console output config")
    for key, value in mode.items():
        if key == "at_startup" and isinstance(value, bool):
            if value:
                run_command(f'pkexec grub_console enable {device}')
                run_command(f'systemctl enable {service}')
            else:
                run_command(f'pkexec grub_console disable {device}')
                run_command(f'systemctl disable {service}')
        elif key == "currently" and isinstance(value, bool):
            run_command(f'systemctl {"start" if value else "stop"} {service}')
        else:
            invalid_key_value += f"Unknown console output config entry: '{key}': '{value}';"
    if invalid_key_value:
        raise InvalidPayloadError(invalid_key_value)


def set_serial(message: bytes) -> None:
    decoded_message = json.loads(message)
    config = get_dict(decoded_message, 'serial')
    if len(config) == 0:
        return

    meta_options: Mapping[str, Any] = decoded_message.pop('meta_options', {})
    ignore_missing_hardware = get_optional_bool(meta_options, "ignore_superflous_config_entries")
    ignored_hardware: List[str] = []

    if len(serial_devices) == 0:
        raise SetSerialError("Device is configured as not having any serial "
                             "devices!!! You can still apply config without "
                             "triggering this error if serials section will be empty.")

    failed = {}
    for name in config:
        if name not in serial_devices:
            if ignore_missing_hardware:
                ignored_hardware.append(name)
            else:
                failed[name] = "unknown device"
            continue
        try:
            toggle_serial(serial_devices[name], config[name]['console_output'])
        except Exception as exc:
            logger.exception(exc)
            failed[name] = str(exc)
    if len(ignored_hardware):
        for name in ignored_hardware:
            config.pop(name)
        logger.info(f"Ignored following devices: {ignored_hardware}")
    new_config = serial_read()['serial']
    for name, subconfig in config.items():
        for when, value in subconfig['console_output'].items():
            if new_config[name]['console_output'][when] != value:
                error = f"state check of {when} failed"
                if name in failed:
                    failed[name] += f"; {error}"
                else:
                    failed[name] = error
    if len(failed) > 0:
        raise SetSerialError(failed)


def set_local_console_login(requested_state: bool) -> None:
    # extract requested state from message
    new_login_state = requested_state

    # get current login state configuration
    current_login_state = get_local_console_login()['local_console']['login']

    if current_login_state != new_login_state:
        # VirtualTerminals (VTs) value is either set to system default to enable
        # or to 0 is to disable local console
        VTs = LOGIND_DEFAULT_NAUTOVTS if new_login_state else 0

        config_logind = CaseSensitiveConfigParser()
        config_logind.read(LOGIND_CONF)
        config_logind['Login']['NAutoVTs'] = str(VTs)
        config_logind['Login']['ReserveVT'] = str(VTs)

        # write file using configparser
        with open(LOGIND_CONF, 'w') as log_conf:
            config_logind.write(log_conf)

        if new_login_state:
            sysctl_action = 'enable'
        else:
            sysctl_action = 'disable'

        # enabling and disabling require all getty services to restart
        # there are LOGIND_DEFAULT_NAUTOVTS+1 services
        for i in range(1, (LOGIND_DEFAULT_NAUTOVTS+1)):
            command = f'systemctl {sysctl_action} --now getty@tty{i}.service'
            run_command(command)
        run_command('systemctl restart systemd-logind')


def set_local_console_syskeys(requested_state: bool) -> None:
    # extract requested state from message
    incomming_syskeys_enabled = requested_state

    # get current login state configuration
    current_syskeys_enabled = get_local_console_syskeys()['local_console']['syskeys']

    if current_syskeys_enabled is not incomming_syskeys_enabled:
        config_system = CaseSensitiveConfigParser()
        config_system.read(SYSTEM_CONF)

        config_sysctl = ConfctlParser(SYSCTL_CONF)

        if incomming_syskeys_enabled:
            config_system['Manager']['CtrlAltDelBurstAction'] = "reboot-force"
            config_sysctl['kernel.sysrq'] = SYSCTL_SYSRQ_REBOOT_VALUE
        else:
            config_system['Manager']['CtrlAltDelBurstAction'] = "none"
            config_sysctl['kernel.sysrq'] = SYSCTL_SYSRQ_IGNORE_VALUE

        with open(SYSTEM_CONF, 'w') as system_conf:
            config_system.write(system_conf)
        config_sysctl.write()

        run_command('systemctl daemon-reload')
        run_command('pkexec sysctl -p')


def set_local_console_config(message: bytes) -> None:
    config = json.loads(message)

    if 'syskeys' in get_dict(config, 'local_console'):
        requested_state = get_bool(get_dict(config, 'local_console'), 'syskeys')
        set_local_console_syskeys(requested_state)
    if 'login' in get_dict(config, 'local_console'):
        requested_state = get_bool(get_dict(config, 'local_console'), 'login')
        set_local_console_login(requested_state)


@empty_message_wrapper
def get_local_console_login(message: bytes) -> Dict[str, Dict[str, bool]]:
    expect_empty_message(message, "get_local_console_login()")

    config_logind = CaseSensitiveConfigParser()
    config_logind.read(LOGIND_CONF)
    NAutoVTs = config_logind.getint('Login', 'NAutoVTs', fallback=1)
    ReserveVT = config_logind.getint('Login', 'ReserveVT', fallback=1)

    # although this is a getter function we need to
    # check if configuration is consistent and set to default if not
    # this fixes any potential manual miss-configurations
    if NAutoVTs != ReserveVT:
        config_logind['Login']['NAutoVTs'] = str(LOGIND_DEFAULT_NAUTOVTS)
        config_logind['Login']['ReserveVT'] = str(LOGIND_DEFAULT_NAUTOVTS)
        with open(LOGIND_CONF, 'w') as log_conf:
            config_logind.write(log_conf)
        NAutoVTs = LOGIND_DEFAULT_NAUTOVTS
        ReserveVT = LOGIND_DEFAULT_NAUTOVTS

    if NAutoVTs > 0 and ReserveVT > 0:
        return {'local_console': {'login': True}}
    else:
        return {'local_console': {'login': False}}


@empty_message_wrapper
def get_local_console_syskeys(message: bytes) -> Dict[str, Dict[str, bool]]:
    expect_empty_message(message, "get_local_console_syskeys()")

    # handling of Ctrl-Alt-Del hot-keys
    config_system = configparser.ConfigParser()
    config_system.read(SYSTEM_CONF)
    ctrl_alt_del_action = config_system.get('Manager', 'CtrlAltDelBurstAction',
                                            fallback='reboot-force')

    # handling of SysRq
    config_sysctl = ConfctlParser(SYSCTL_CONF, default=SYSCTL_SYSRQ_REBOOT_VALUE)
    sysrq_value = config_sysctl['kernel.sysrq']

    if ((ctrl_alt_del_action == "none" and sysrq_value != SYSCTL_SYSRQ_IGNORE_VALUE) or
            (ctrl_alt_del_action == "reboot-force" and sysrq_value != SYSCTL_SYSRQ_REBOOT_VALUE)):
        # this should never happen - mismatch configuration
        # based on CtrlAltDel action we set same for SysRq
        if ctrl_alt_del_action == "none":
            config_sysctl['kernel.sysrq'] = SYSCTL_SYSRQ_IGNORE_VALUE
        else:
            config_sysctl['kernel.sysrq'] = SYSCTL_SYSRQ_REBOOT_VALUE
        config_sysctl.write()

        run_command('pkexec sysctl -p')

    if ctrl_alt_del_action == "none":
        return {'local_console': {'syskeys': False}}
    else:
        return {'local_console': {'syskeys': True}}


@empty_message_wrapper
def get_local_console_config(message: bytes) -> Dict[str, Dict[str, bool]]:
    expect_empty_message(message, "get_local_console_config")

    login_config = get_local_console_login()
    syskeys_config = get_local_console_syskeys()

    local_console_config = {}
    key = 'local_console'
    local_console_config[key] = {**login_config[key], **syskeys_config[key]}
    return local_console_config


def remap_ssh_config(config: Dict[str, str]) -> Dict[str, str]:
    """
    Remap values from CLI to ssh_config and vice versa
    This function remap "on" to "yes"
    and "off" to "no"
    """
    value_map = {"yes": "on", "no": "off", "on": "yes", "off": "no"}
    for key, value in config.items():
        # Since ssh config can contain antoher Dict with all ssh keys from users and we can not remap Dict to string
        # TODO it would be safer to remap just expected keys instead of all keys with str values...
        # TODO even if we leave it as is, we shall check if order of tests is optimal
        if value != "" and isinstance(value, str):
            try:
                config[key] = value_map[value]
            except KeyError:
                raise InvalidPayloadError(f"Key '{key}' has invalid value '{value}' --- allowed is 'on' or 'off' or ''")
    return config


def set_ssh_config(message: bytes) -> None:
    incoming_config = remap_ssh_config(get_dict(json.loads(message), "sshconfig"))
    maxsessions = get_optional_int(incoming_config, "maxsessions")
    maxstartups = get_optional_int(incoming_config, "maxstartups")
    if maxsessions is not None:
        SSH_MAXSESSIONS.write_text(f'MaxSessions {maxsessions}')
    if maxstartups is not None:
        SSH_MAXSTARTUPS.write_text(f'MaxStartups {maxstartups}')

    config = get_ssh_config(False)["sshconfig"]
    config['key_auth'] = get_str_with_default(incoming_config, 'key_auth', default=config['key_auth'])
    config['password_auth'] = get_str_with_default(incoming_config, 'password_auth', default=config['password_auth'])
    if config["key_auth"] == "no" and config["password_auth"] == "no":
        if 'key_auth' in incoming_config and 'password_auth' in incoming_config:
            raise InvalidParameterError("At least one authentication method has to be enabled")
        if 'key_auth' in incoming_config:
            raise InvalidPreconditionError("You cannot turn off key_auth while password_auth is already disabled")
        raise InvalidPreconditionError("You cannot turn off password_auth while key_auth is already disabled")

    if "publickeys" in incoming_config:
        public_keys = get_dict(incoming_config, "publickeys")
        data = {"action": SshAction.SET_ALL, "data": public_keys}
        message = bytearray(json.dumps(data), encoding="UTF-8")
        user_status = get_dict(send_and_wait_for_response_on_socket(message), "user_status")

    enforced_password_auth_enabling = False
    if config["key_auth"] == "yes" and config["password_auth"] == "no" and not check_if_admin_has_public_ssh_key():
        if "publickeys" not in incoming_config:
            raise InvalidPreconditionError("Built-in admin account requires ssh key before enabling key only authentication")
        enforced_password_auth_enabling = True
        logger.warning("Enforcing enabled password_auth because admin has no public keys after setting new config")
        config["password_auth"] = "yes"

    with open(SSH_AUTH_CONFIG, "w") as fd:
        fd.write(SSH_AUTH_TEMPLATE.format(pass_auth=config["password_auth"], key_auth=config["key_auth"]))

    if "publickeys" in incoming_config:
        failed_users = [user for user in user_status if user_status[user].startswith(RESPONSE_FAILURE)]
        if len(failed_users) > 0:
            for user in failed_users:
                logger.warning(f"Failed setting ssh key for {user}: {user_status[user]}")
        if enforced_password_auth_enabling:
            if "admin" in failed_users:
                raise SSHKeyManagementError(f"Setting of authorized keys for {failed_users} failed and there were "
                                            "no valid keys for admin afterwards, therefore password authentication is "
                                            "enabled globally. Please review logs for more details.")
            if len(failed_users) > 0:
                raise SSHKeyManagementError("There was no authorized keys for admin therefore password authentication is "
                                            "enabled globally. Additionally there was failure in setting authorized "
                                            f"keys for {failed_users}. Please review logs for more details.")
            raise InvalidParameterError("There were no keys for admin therefore password authentication is enabled globally.")
        if len(failed_users) > 0:
            raise SSHKeyManagementError(f"Failed setting of sshkeys for {failed_users}. Please review logs for more details")


def get_ssh_config(return_remapped: bool = True) -> Dict[str, Dict[str, Any]]:
    with open(SSH_AUTH_CONFIG, "r") as fd:
        auth_config_raw = fd.read()
    auth_config = auth_config_raw.splitlines()
    # By default both methods are enabled, if there is no line in config
    # for specific method system assumes that it is set to yes
    config: Dict[str, Any] = {"password_auth": "yes", "key_auth": "yes"}
    for line in auth_config:
        if line.startswith("PasswordAuthentication"):
            config["password_auth"] = line.split(" ")[1]
        elif line.startswith("PubkeyAuthentication"):
            config["key_auth"] = line.split(" ")[1]
        else:
            logger.warn(f"Unknow value {line} in {SSH_AUTH_CONFIG}")
    new_config: Dict[str, Any] = remap_ssh_config(config) if return_remapped else config
    data = {"action": SshAction.GET_ALL}
    message = bytearray(json.dumps(data), encoding="UTF-8")
    response = send_and_wait_for_response_on_socket(message)
    config["publickeys"] = get_dict(response, "keys")
    u_s = get_dict(response, "user_status")
    new_config["unreadable_users"] = {u: s[len(RESPONSE_FAILURE):] for (u, s) in u_s.items() if s.startswith(RESPONSE_FAILURE)}

    new_config["maxsessions"] = int(SSH_MAXSESSIONS.read_text().split()[1])
    # for now the content should be 'MaxStartups start' where 'start' is a digit
    # this may be in the future     'MaxStartups start:full:rate'
    # we split by ':' and take the first element
    new_config["maxstartups"] = int(SSH_MAXSTARTUPS.read_text().split()[1].split(":")[0])
    return {"sshconfig": new_config}


def ssh_config_show(message: bytes) -> Dict[str, Dict[str, Any]]:
    expect_empty_message(message, "ssh_config_show()")
    return get_ssh_config()


def list_ssh_keys(message: bytes) -> Dict[str, Any]:
    ssh_keys = json.loads(message)
    ssh_keys["action"] = SshAction.SHOW
    message = bytearray(json.dumps(ssh_keys), encoding="UTF-8")
    return get_dict(send_and_wait_for_response_on_socket(message), "keys")


def add_ssh_key(message: bytes) -> None:
    ssh_keys = json.loads(message)
    username = get_str(ssh_keys, 'username')
    primary_group = get_user_primary_group(username)
    if primary_group not in SSH_KEY_ALLOWED_PRIMARY_GROUPS:
        raise InvalidPreconditionError(f"You can not modyify keys for user {username}")
    ssh_keys["action"] = SshAction.ADD
    message = bytearray(json.dumps(ssh_keys), encoding="UTF-8")
    send_and_wait_for_response_on_socket(message)


def remove_ssh_key(message: bytes) -> None:
    ssh_keys = json.loads(message)
    username = get_str(ssh_keys, 'username')
    primary_group = get_user_primary_group(username)
    if primary_group in SSH_KEY_ALLOWED_PRIMARY_GROUPS:
        raise InvalidPreconditionError(f"You can not modyify keys for user {username}")
    ssh_keys["action"] = SshAction.REMOVE
    ssh_keys["index"] = get_int(ssh_keys, 'index')
    message = bytearray(json.dumps(ssh_keys), encoding="UTF-8")
    send_and_wait_for_response_on_socket(message)


def install_localcert(message: bytes) -> None:
    src_path = Path(json.loads(message.decode("utf-8")))

    if not src_path.exists():
        raise InvalidParameterError(f"Source: '{src_path}' does not exist")
    try:
        with src_path.open():  # open just to check if file is readable
            pass
    except Exception:
        raise InvalidParameterError(f"Source: '{src_path}' is not readable")

    shutil.copy(src_path, CERT_STORE_PATH)
    run_command("pkexec /usr/sbin/update-ca-certificates")


# TODO remove possible code duplication with mgmtd-compose.py:docker_compose_proxy_add
def add_proxy(message: bytes, *, remove_missing: bool = False) -> None:
    proxy_data = json.loads(message)
    proxies = get_dict(proxy_data, 'proxy_servers')
    generic_config: MutableMapping[str, Any] = {}

    key_prefixes = ('http', 'https')

    def key(prefix: str) -> str:
        return f'{prefix}_proxy'

    keys = list(key(prefix) for prefix in key_prefixes)

    if len(proxies) != 2:
        for received_key in proxies:
            if received_key not in keys:
                raise InvalidPayloadError(f"Unexpected entry in proxy_servers: {received_key}")

    if PROXY_CONFIG_FILE.exists():
        generic_config = toml.loads(PROXY_CONFIG_FILE.read_text())

    for prefix in key_prefixes:
        value = get_optional_str(proxies, key(prefix))
        if len(value) > 0:
            generic_config[key(prefix)] = value
        elif remove_missing:
            generic_config.pop(key(prefix), value)

    if len(generic_config) > 0:
        # we replace spaces around '=' in toml so it becomes valid shell code to be sourced by proxy.sh
        PROXY_CONFIG_FILE.write_text(toml.dumps(generic_config).replace(' = ', '='))
    else:
        PROXY_CONFIG_FILE.write_text("# No proxies defined")
    # WARNING We were reloading docker here if reload_daemons was set to true in
    # incomming message, but now we do it only in mgmtd-compose.py
    # --- if we find out that some other (than docker) deamons need to be
    # reloaded after setting new proxy, we will need to renistate parsing for
    # that message part and reload daemons as needed


def del_proxy(message: bytes) -> None:
    data = json.loads(message)
    generic_config = {}
    if PROXY_CONFIG_FILE.exists():
        generic_config = toml.loads(PROXY_CONFIG_FILE.read_text())

    for proxy, to_delete in data.items():
        if to_delete:
            generic_config.pop(proxy, None)

    if len(generic_config) > 0:
        # we replace spaces around '=' in toml so it becomes valid shell code to be sourced by proxy.sh
        PROXY_CONFIG_FILE.write_text(toml.dumps(generic_config).replace(' = ', '='))
    else:
        PROXY_CONFIG_FILE.write_text("# No proxies defined")


def set_proxy_config(message: bytes) -> None:
    add_proxy(message, remove_missing=True)


def proxy_config_read() -> Mapping[str, Any]:
    if PROXY_CONFIG_FILE.exists():
        return {'proxy_servers': toml.loads(PROXY_CONFIG_FILE.read_text())}
    return {'proxy_servers': None}


def get_proxy_config(message: bytes) -> Mapping[str, Any]:
    expect_empty_message(message, "get_proxy_config()")
    return proxy_config_read()


def set_logintimeout_config(message: bytes) -> None:
    timeout = get_optional_int(json.loads(message), "login_timeout")
    if timeout is None or timeout == 0:
        LOGIN_TIMEOUT_CONFIG_FILE.unlink(missing_ok=True)
    elif timeout < 10:
        raise InvalidParameterError("Login timeout lower than 10 second would make human operator to life miserable")
    else:
        LOGIN_TIMEOUT_CONFIG_FILE.write_text(f'TMOUT={timeout}')


def logintimeout_read() -> Mapping[str, Any]:
    if LOGIN_TIMEOUT_CONFIG_FILE.exists():
        # toml can successfuly parse our single line shell script which just sets variable :)
        return {'login_timeout': toml.loads(LOGIN_TIMEOUT_CONFIG_FILE.read_text())}
    return {'login_timeout': None}


def get_logintimeout_config(message: bytes) -> Mapping[str, Any]:
    expect_empty_message(message, "get_logintimeout_config()")
    return logintimeout_read()


def check_if_user_exists(username: str) -> bool:
    output = run_command_unchecked(f"id -u {quote(username)}")
    return bool(output.returncode == SUCCESS)


def add_user(username: str, password: str, gname: str, group_home_path: Path) -> None:
    if check_if_user_exists(username):
        raise InvalidPreconditionError(f"User {username} already exists")
    if gname == ADMIN_SYSTEM_GROUP:
        extra_group = "-G iotedge,docker,zmq"
    else:
        extra_group = "-G zmq"
    cmd = f"pkexec /usr/sbin/useradd -g {gname} {extra_group} -m -d {quote(str(group_home_path / username))}  {quote(username)}"
    if len(password) > 0:
        hashed_password = run_command(
            f"openssl passwd -1 {quote(password)}", is_confidential=True
        ).stdout.decode('ascii').strip()
        cmd = cmd + f" -p {quote(hashed_password)}"
    run_command(cmd)


def remove_user(username: str, *, deletehome: bool) -> None:
    if not check_if_user_exists(username):
        raise InvalidPreconditionError(f"No such user: {username}")
    if deletehome:
        cmd = f"pkexec /usr/sbin/userdel -r {quote(username)}"
    else:
        cmd = f"pkexec /usr/sbin/userdel {quote(username)}"
    result = run_command_unchecked(cmd)
    if result.returncode == 8:
        raise InvalidPreconditionError(f"User {username} is currently logged in")
    result.check_returncode()


def manage_user(message: bytes) -> Optional[Dict[str, List[Dict[str, str]]]]:
    user_data = json.loads(message)
    action = get_enum_str(user_data, 'action', [ADD_USER, REMOVE_USER, SHOW_USERS])
    if action == SHOW_USERS:
        return get_user_list()
    username = get_str(user_data, 'username')
    if action == ADD_USER:
        password = get_str(user_data, 'password')
        add_user(username, password, *GROUP_DATA[get_enum_str(user_data, 'group', GROUP_DATA.keys())])
    elif action == REMOVE_USER:
        remove_user(username, deletehome=get_bool(user_data, 'deletehome'))
    return None


def set_motd(message: bytes) -> None:
    user_data_text = json.loads(message)
    MOTD_FILE.write_text(user_data_text.get('motd', ''))


@empty_message_wrapper
def motd_get_config(message: bytes) -> Dict[str, str]:
    expect_empty_message(message, "motd_get_config()")
    return {"motd": MOTD_FILE.read_text()}


def set_issue(message: bytes) -> None:
    user_data_text = json.loads(message)
    # Preserve exact content (including trailing newline); allow missing key
    ISSUE_FILE.write_text(user_data_text.get('issue', ''))


@empty_message_wrapper
def issue_get_config(message: bytes) -> Dict[str, str]:
    expect_empty_message(message, "issue_get_config()")
    return {"issue": ISSUE_FILE.read_text()}


def overcommit_memory_get(message: bytes) -> Dict[str, str]:
    expect_empty_message(message, "overcommit_memory_get()")
    content = Path("/proc/sys/vm/overcommit_memory").read_text().strip()
    status = "enabled" if content == "0" else "disabled"
    return {"overcommit_memory": status}


def overcommit_memory_set(message: bytes) -> None:
    option = json.loads(message)["overcommit_memory"]
    data = {"file": "/proc/sys/vm/overcommit_memory"}
    match option:
        case "enable" | "default":
            data["flag"] = "0"
        case "disable":
            data["flag"] = "2"
        case _:
            raise NotImplementedError

    parser = ConfctlParser(SYSCTL_CONF)
    parser["vm.overcommit_memory"] = data["flag"]
    parser.write()

    message = bytearray(json.dumps(data), encoding="utf-8")
    send_and_wait_for_response_on_socket(message, str(KERNEL_SOCKET_PATH))


@empty_message_wrapper
def user_password_hash_get(message: bytes) -> Dict[str, Dict[str, str]]:
    expect_empty_message(message, "user_password_hash_get()")
    data = send_and_wait_for_response_on_socket(bytearray(), str(SHADOW_SOCKET_PATH))
    return {"user_password_hashes": get_dict(data, "user_password_hashes")}


def user_password_hash_set(message: bytes) -> None:
    data = json.loads(message)
    user_password_hashes = get_dict(data, "user_password_hashes")
    users: list[dict[str, str]] = get_user_list()["users"]
    user_names: list[str] = [user["name"] for user in users]

    for username in user_password_hashes:
        try:
            pwd.getpwnam(username)
        except KeyError:
            raise InvalidPayloadError(f"User {username} does not exist")
        if username not in user_names:
            raise InvalidPayloadError(f"User {username} password cannot be changed")

    send_and_wait_for_response_on_socket(
        bytearray(json.dumps(user_password_hashes), encoding="utf-8"),
        str(SHADOW_SOCKET_PATH),
    )


def serialnumber_get(message: bytes) -> Dict[str, str]:
    expect_empty_message(message, "serialnumber_get()")
    return {"serial_number": get_serial_number()}


def perform_factory_reset(message: bytes) -> str:
    expect_empty_message(message, "perform_factory_reset()")
    run_command("pkexec /usr/sbin/factory_reset")
    run_command("bash -c \"(sleep 5; reboot)& \" ", capture_output=False)
    return f"{RESPONSE_OK} Device will reboot in few seconds"


@empty_message_wrapper
def logrotate_get_config(message: bytes) -> Dict[str, Dict[str, Any]]:
    expect_empty_message(message, "logrotate_get_config()")
    logrotate_config = logrotate_config_file.read_text().splitlines()
    config: Dict[str, Any] = {}
    #  see logrotate_template variable above for potential lines
    for line in logrotate_config:
        match line.split():
            case [x, y] if x in ("rotate", "maxsize"):
                found_integer = re.match(r'\d+', y)
                assert found_integer is not None
                config[x] = int(found_integer.group())
            case [x] if x in (HOUR, DAY, WEEK, MONTH):
                config["period"] = x
    output = {"logrotate": config}
    return output


def logrotate_set_config(message: bytes) -> None:
    # Logrotate is overprotective and does not allow group write permission on
    # its config files. Our daemon runs as mgmtd user and we have acl set on
    # logrotate config files to allow it to write to those files, but the way
    # acl's work is that group permissions are masking out acl user permissions,
    # so we need temporarily change group permission on the file
    # TODO change behaviour of logrotate, as it is overprotective
    def write_making_temporarily_group_writable(file_name: Path, contents: Union[str, List[str]]) -> None:
        try:
            run_command(f"pkexec /bin/chmod g+w {file_name}")
            with open(file_name, "w") as file:
                match contents:
                    case str():
                        file.write(contents)
                    case list():
                        file.writelines(contents)
                    case _:
                        raise RuntimeError("Unrecognized type for file contents")
        finally:
            run_command(f"pkexec /bin/chmod g-w {file_name}")

    user_data = json.loads(message)['logrotate']
    rotate = get_int(user_data, 'rotate')
    period = get_enum_str(user_data, 'period', [HOUR, DAY, WEEK, MONTH])
    size = get_int(user_data, 'maxsize')
    global_config_change = True
    global_config_line = 0
    line_found = False

    if size < 1:
        raise InvalidParameterError("size must be greater than 0")

    if rotate < 0:
        raise InvalidParameterError("rotate must be greater than or equal to 0")

    # for chronological order (in minutes)
    chrono = {'hourly': 60, 'daily': 1440, 'weekly': 10080, 'monthly': 40320}

    with open(logrotate_global_config_file, 'r') as file:
        global_config = file.readlines()

    for line in global_config:
        line = line.strip()
        if line in chrono:
            line_found = True
            logger.info("Found value for logrotate global period")
            global_config_line = global_config.index(f'{line}\n')
            if global_config[global_config_line] == period:
                global_config_change = False
            if (chrono[period] <= chrono["daily"]):
                logger.info("changing global logrotate configuration as global period is longer")
                global_config[global_config_line] = period + "\n"
            else:
                logger.info("changing global logrotate configuration to: daily")
                global_config[global_config_line] = "daily\n"

    if global_config_change:
        write_making_temporarily_group_writable(logrotate_global_config_file, global_config)
    if not line_found:
        logger.error("Value not found in logrotate global config file")

    logrotate_config = logrotate_template.format(rotate=rotate, period=period, size=size)
    write_making_temporarily_group_writable(logrotate_config_file, logrotate_config)


def grant_docker_volumes_access_to_admins(message: bytes) -> None:
    expect_empty_message(message, "get_docker_files_access()")
    # https://serverfault.com/questions/444867/linux-setfacl-set-all-current-future-files-directories-in-parent-directory-to
    run_command("pkexec setfacl -m u:admin:rx /data/docker")  # allow listing content of /data/docker
    run_command("pkexec setfacl -Rm u:admin:rwx /data/docker/volumes")  # only set access for already existing files
    run_command("pkexec setfacl -Rdm u:admin:rwx /data/docker/volumes")  # set access for new files


def set_config_step_init(message: bytes, from_part: bytes, message_id: bytes) -> com_client.Async:
    def background_task(message: bytes, from_part: bytes, message_id: bytes) -> None:
        with DEVICE_SET_CONFIG_LOCK.transaction("Global lock for loading device seetings from file"):
            config = json.loads(message)
            meta_options = get_optional_dict(config, 'meta_options')
            if meta_options is None:
                meta_options = {}
            logger.debug(f"meta_options: {meta_options}")
            setconfig = SetConfig(_client, logger)
            setconfig.prepare_backup_config()
            continue_despite_errors = meta_options.pop("continue_despite_errors", False)
            ignored_keys = setconfig.set_config_file(config, continue_despite_errors=continue_despite_errors)
            setconfig.execute_and_wait()
            if get_optional_bool(meta_options, "ask_for_affirmation"):
                warn_about_ignored_keys = True if len(ignored_keys) else False
                setconfig.confirm_config(from_part, message_id, warn_about_ignored_keys=warn_about_ignored_keys).wait()
            else:
                if len(setconfig.errors):
                    setconfig.rollback_config()
                    error = TransactionRolledBackError("New configuration was rolled back due to errors")
                    error_response = convert_exception_to_message_failure_status(error)
                    _client.respond(f"dev.set_config{RESPONSE_SUFFIX}", error_response, from_part, message_id)
                else:
                    setconfig.remove_backup()
                    _client.respond(f"dev.set_config{RESPONSE_SUFFIX}",
                                    f"{RESPONSE_OK}: New configuration applied.", from_part, message_id)
    background_thread = KillerThread(target=background_task, args=(message, from_part, message_id))
    background_thread.start()
    return com_client.Async()


_parser = argparse.ArgumentParser(prog='Device config daemon')
com_client.add_command_line_params(_parser)
_args = _parser.parse_args()
_client = com_client.Client(args=_args)


def main() -> None:
    def in_bg(topic: str, fun: com_client.SyncHandlerCallable, post_respond: Optional[Callable[[Any], None]] = None) -> None:
        messages[topic] = background(fun, com_client.respond_to(_client, topic), post_respond=post_respond)

    messages = {}
    smartems = SmartEMS(_client)
    in_bg(topics.azure.set_config, guarded(azure.set_config))
    messages[topics.azure.get_config] = guarded(sync(azure.get_config(with_privates=False)))
    messages[topics.azure.get_config_with_privates] = guarded(sync(azure.get_config(with_privates=True)))
    in_bg(topics.azure.get_config_file, guarded(azure.get_configfile))
    in_bg(topics.azure.set_config_file, guarded(azure.set_configfile))
    in_bg(topics.azure.set_partial_config_file, guarded(azure.set_option))
    in_bg(topics.azure.set_tpm, guarded(azure.set_tpm))
    in_bg(topics.azure.set_x509, guarded(azure.set_x509))
    in_bg(topics.azure.set_cert, guarded(azure.set_cert))
    in_bg(topics.azure.set_hostname, guarded(azure.set_hostname))
    in_bg(topics.azure.remove_cert, guarded(azure.remove_cert))
    in_bg(topics.azure.set_connection_string, guarded(azure.set_connection_string))
    in_bg(topics.azure.clean_keys, guarded(azure.clean_keys))
    in_bg(topics.dev.tpm.get_config, guarded(tpm_get))
    messages[topics.dev.get_config] = guarded(get_config_step_init(with_privates=False))
    messages[topics.dev.reboot] = guarded(sync(reboot_device))
    messages[topics.dev.get_config_with_privates] = guarded(get_config_step_init(with_privates=True))
    messages[topics.dev.set_config] = guarded(set_config_step_init)
    messages[topics.dev.serial.set_config] = guarded(sync(set_serial))
    messages[topics.dev.serial.get_config] = guarded(sync(get_serial))
    messages[topics.dev.manage_user] = guarded(sync(manage_user))
    messages[topics.dev.motd.set] = guarded(sync(set_motd))
    messages[topics.dev.motd.set_config] = guarded(sync(set_motd))
    messages[topics.dev.motd.get_config] = guarded(sync(motd_get_config))
    messages[topics.dev.issue.set] = guarded(sync(set_issue))
    messages[topics.dev.issue.set_config] = guarded(sync(set_issue))
    messages[topics.dev.issue.get_config] = guarded(sync(issue_get_config))
    messages[topics.dev.overcommit_memory.get] = guarded(sync(overcommit_memory_get))
    messages[topics.dev.overcommit_memory.set] = guarded(sync(overcommit_memory_set))
    messages[topics.dev.get_serial_number] = guarded(sync(serialnumber_get))
    messages[topics.dev.perform_factory_reset] = guarded(sync(perform_factory_reset))
    messages[topics.dev.logrotate.set_config] = guarded(sync(logrotate_set_config))
    messages[topics.dev.logrotate.get_config] = guarded(sync(logrotate_get_config))
    messages[topics.smart_ems.set_config] = guarded(sync(smartems.set_ems_config))
    messages[topics.smart_ems.get_config] = guarded(sync(smartems.get_ems_config))
    in_bg(topics.smart_ems.check_smart_ems, guarded(smartems.check_smart_ems))
    messages[topics.smart_ems.manage_cert] = guarded(sync(smartems.manage_cert))
    messages[topics.dev.datetime.get_config] = guarded(sync(date_time.get_config))
    messages[topics.dev.datetime.set_config] = guarded(sync(date_time.set_config))
    messages[topics.dev.datetime.set_timezone] = guarded(sync(date_time.set_timezone))
    messages[topics.dev.datetime.show] = guarded(sync(date_time.show_time))
    messages[topics.dev.datetime.set_ntp_server] = guarded(sync(date_time.set_ntp_server))
    messages[topics.dev.datetime.manage_ntp_service] = guarded(sync(date_time.manage_ntp_service))
    messages[topics.dev.ssh.set_config] = guarded(sync(set_ssh_config))
    # TODO behaves differently than other get_config handlers!
    messages[topics.dev.ssh.get_config] = guarded(sync(ssh_config_show))
    messages[topics.dev.ssh.list_keys] = guarded(sync(list_ssh_keys))
    messages[topics.dev.ssh.add_key] = guarded(sync(add_ssh_key))
    messages[topics.dev.ssh.remove_key] = guarded(sync(remove_ssh_key))
    messages[topics.dev.install_localcert] = guarded(sync(install_localcert))
    messages[topics.dev.proxy.add] = guarded(sync(add_proxy))
    messages[topics.dev.proxy.delete] = guarded(sync(del_proxy))
    messages[topics.dev.proxy.set_config] = guarded(sync(set_proxy_config))
    messages[topics.dev.proxy.get_config] = guarded(sync(get_proxy_config))
    messages[topics.dev.logintimeout.set_config] = guarded(sync(set_logintimeout_config))
    messages[topics.dev.logintimeout.get_config] = guarded(sync(get_logintimeout_config))
    messages[topics.dev.docker_volumes_access] = guarded(sync(grant_docker_volumes_access_to_admins))
    messages[topics.dev.local_console.login.get_config] = guarded(sync(get_local_console_login))
    messages[topics.dev.local_console.syskeys.get_config] = guarded(sync(get_local_console_syskeys))
    messages[topics.dev.local_console.set_config] = guarded(sync(set_local_console_config))
    messages[topics.dev.local_console.get_config] = guarded(sync(get_local_console_config))
    messages[topics.dev.user.password_hash.get_config] = guarded(sync(user_password_hash_get))
    messages[topics.dev.user.password_hash.set_config] = guarded(sync(user_password_hash_set))

    _client.register_responders(messages)

    if _client.has_responding_handler(topics.dev.set_config):
        check_if_backup_config_exists(_client)
        smartems.check_if_smartems_transaction_in_progress()

    while True:
        try:
            _client.wait_and_receive()
        except _client.LostRequestList as lre:
            logger.warning(f"Received LostRequestList: {lre}")
        except _client.ConnectionResetError as cre:
            logger.warning(f"Received ConnectionResetError: {cre}")


if __name__ == "__main__":
    main()
