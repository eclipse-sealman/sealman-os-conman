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
Daemon responsible for ovpn network tunnel configuration.
"""
from __future__ import annotations

# Standard imports
import argparse
import json
from pathlib import Path
import sys
from shlex import quote
from subprocess import CompletedProcess
from typing import Any, Callable, Dict, Union, MutableMapping

# Local imports
import mpa.communication.topics as topics
from .common import get_ovpn_configs, OVPN_CONFIG_DIR, OVPN_CONFIG_FILE_ALREADY_EXISTS, OvpnAction
from mpa.common.common import RESPONSE_FAILURE, RESPONSE_OK, FileExtension
from mpa.communication import client as com_client
from mpa.communication.client import guarded, sync
from mpa.communication.status_codes import SUCCESS
from mpa.communication.process import run_command
from mpa.communication.process import run_command_unchecked
from mpa.common.logger import Logger
from mpa.config.configfiles import ConfigFiles
from mpa.parser import openvpn_parser

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")


_parser = argparse.ArgumentParser(prog='Ovpn config daemon')
com_client.add_command_line_params(_parser)
_args = _parser.parse_args()
_client = com_client.Client(args=_args)

config_files = ConfigFiles()
config_files.add("openvpndir", OVPN_CONFIG_DIR.stem)
config_files.verify()
OVPN_CONFIG_CONNECTIONS = OVPN_CONFIG_DIR / "connections_info"


def systemctl_tunnel(what: str, config_file: Path,
                     run_cmd: Callable[[str], CompletedProcess[bytes]] = run_command) -> CompletedProcess[bytes]:
    # TODO verify that tunnel name does not contain special chars or mangle name according to systemd rules
    service = f"openvpn-client@{config_file.name}"
    # what is not comming from user and it may contain spaces, so we don't want to quote it
    return run_cmd(f"systemctl {what} {quote(service)}")


def apply_autostart(autostart: bool, config_file: Path) -> CompletedProcess[bytes]:
    return systemctl_tunnel(f"{'enable' if autostart else 'disable'} --now", config_file)


def systemctl_check_if(what: str, config_file: Path) -> bool:
    result = systemctl_tunnel(what, config_file, run_command_unchecked)
    return result.returncode == SUCCESS


def is_enabled(config_file: Path) -> bool:
    return systemctl_check_if("is-enabled --quiet", config_file)


def is_active(config_file: Path) -> bool:
    return systemctl_check_if("is-active --quiet", config_file)


def list_ovpn_configs(message: bytes) -> MutableMapping[str, Any]:
    if message and len(message) > 0:
        logger.warning(f"Non empty message received in get_config: {message.decode('UTF-8')}")
    config: MutableMapping[str, Any] = {"ovpn": {}}
    ovpn_configs = get_ovpn_configs()
    for config_file in ovpn_configs:
        config_content = openvpn_parser.encode_from_file(config_file)
        config["ovpn"][config_file.stem] = {"config": config_content, "autostart": is_enabled(config_file)}
    return config


def remove_tunnel(message: bytes) -> str:
    to_remove = json.loads(message)
    config_file = OVPN_CONFIG_DIR / f"{to_remove['tunnel_name']}{FileExtension.OVPN.value}"
    if not config_file.is_file():
        return f"{RESPONSE_FAILURE} config file {config_file} not found for tunnel {to_remove['tunnel_name']}"
    systemctl_tunnel("disable --now", config_file)
    config_file.unlink(missing_ok=False)
    return RESPONSE_OK


def add_tunnel(message: bytes) -> str:
    config = json.loads(message)
    if not ('config' in config and isinstance(config['config'], str) and len(config['config']) > 0):
        return f"{RESPONSE_FAILURE} config data missing in request"
    config_file_path = OVPN_CONFIG_DIR / f"{config['tunnel_name']}{FileExtension.OVPN.value}"
    if config_file_path.exists() and not config['overwrite']:
        logger.warning(f"Refused to overwrite tunnel config file {config_file_path} without explicit overwrite request")
        return OVPN_CONFIG_FILE_ALREADY_EXISTS
    with open(config_file_path, "w") as config_file:
        config_file.write(config['config'])
    apply_autostart(config['autostart'], config_file_path)
    return RESPONSE_OK


def set_config(message: bytes) -> None:
    config = json.loads(message)["ovpn"]
    for tunnel in config:
        config_file = OVPN_CONFIG_DIR / f"{tunnel}{FileExtension.OVPN.value}"
        openvpn_parser.decode_to_file(config[tunnel]['config'], config_file)
        apply_autostart(config[tunnel]['autostart'], config_file)


def handle_autostart(message: bytes) -> Union[Dict[str, Any], str]:
    # TODO unify with handle_connection
    to_autostart = json.loads(message)
    config_file = OVPN_CONFIG_DIR / f"{to_autostart['tunnel_name']}{FileExtension.OVPN.value}"
    if not config_file.is_file():
        return f"{RESPONSE_FAILURE} config file {config_file} not found for tunnel {to_autostart['tunnel_name']}"
    if to_autostart["action"] == OvpnAction.STATUS.value:
        return {"autostart": is_enabled(config_file)}
    if to_autostart["action"] == OvpnAction.ENABLE.value:
        systemctl_tunnel("enable", config_file)
        return RESPONSE_OK
    if to_autostart["action"] == OvpnAction.DISABLE.value:
        systemctl_tunnel("disable", config_file)
        return RESPONSE_OK
    return f"{RESPONSE_FAILURE} unrecognized action: {to_autostart['action']}"


def handle_connection(message: bytes) -> Union[Dict[str, Any], str]:
    # TODO unify with handle_autostart
    to_connect = json.loads(message)
    config_file = OVPN_CONFIG_DIR / f"{to_connect['tunnel_name']}{FileExtension.OVPN.value}"
    if not config_file.is_file():
        return f"{RESPONSE_FAILURE} config file {config_file} not found for tunnel {to_connect['tunnel_name']}"
    if to_connect["action"] == OvpnAction.STATUS.value:
        return {"connected": is_active(config_file)}
    if to_connect["action"] == OvpnAction.ENABLE.value:
        systemctl_tunnel("start", config_file)
        return RESPONSE_OK
    if to_connect["action"] == OvpnAction.DISABLE.value:
        systemctl_tunnel("stop", config_file)
        return RESPONSE_OK
    return f"{RESPONSE_FAILURE} unrecognized action: {to_connect['action']}"


def list_tunnels(message: bytes) -> Union[Dict[str, Any], str]:
    ovpn_configs = get_ovpn_configs()
    configs: Dict[str, Any] = {}
    configs["tunnels"] = []
    for config_file in ovpn_configs:
        configs["tunnels"].append(config_file.stem)
    return configs


def tunnel_status(messages: bytes) -> Union[Dict[str, Any], str]:
    ovpn_configs = get_ovpn_configs()
    response: Dict[str, Any] = {}
    response["tunnels"] = {}
    for config_file in ovpn_configs:
        if is_active(config_file):
            info_file = OVPN_CONFIG_CONNECTIONS / f"{config_file.stem}.ovpn.info"
            if info_file.exists():
                with open(info_file, "r") as f:
                    info = json.loads(f.read())
                    info["status"] = "Tunnel is up"
            else:
                info = "No information about this tunnel available"
        else:
            info = {"status": "Tunnel is down"}
        response["tunnels"].update({config_file.stem: info})
    return response


def main() -> None:
    messages = {}
    messages[topics.net.ovpn.add_tunnel] = guarded(sync(add_tunnel))
    messages[topics.net.ovpn.remove_tunnel] = guarded(sync(remove_tunnel))
    messages[topics.net.ovpn.get_config] = guarded(sync(list_ovpn_configs))
    messages[topics.net.ovpn.set_config] = guarded(sync(set_config))
    messages[topics.net.ovpn.set_autostart] = guarded(sync(handle_autostart))
    messages[topics.net.ovpn.set_tunnel_state] = guarded(sync(handle_connection))
    messages[topics.net.ovpn.list_tunnels] = guarded(sync(list_tunnels))
    messages[topics.net.ovpn.tunnels_status] = guarded(sync(tunnel_status))

    _client.register_responders(messages)

    while True:
        _client.wait_and_receive()


if __name__ == "__main__":
    main()
