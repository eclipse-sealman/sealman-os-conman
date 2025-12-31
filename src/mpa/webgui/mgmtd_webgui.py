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

# Standard imports
import json
import re
import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Union

# Third party imports
#  Unfortunately, this module does not provide type information
import nginx  # type: ignore

# Local imports
from mpa.communication.common import expect_empty_message, get_service_status, InvalidParameterError
from mpa.communication import client as com_client
from mpa.communication.message_parser import get_bool, get_dict, get_int
from mpa.communication.process import run_command
from mpa.communication.client import guarded
from mpa.communication.client import sync
from mpa.config.configfiles import ConfigFiles
import mpa.communication.topics as topics
from mpa.common.logger import Logger

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")

config_files = ConfigFiles()
nginx_config = config_files.add("nginx_config", "nginx/sites-available/gui.conf")
nginx_config_default = config_files.add("nginx_config_default", "nginx/sites-available/gui.conf.default")
config_files.verify()


@dataclass
class ServiceStatus:
    is_nginx_active: bool
    is_backend_active: bool
    is_nginx_enabled: bool
    is_backend_enabled: bool
    is_certificate_service_enabled: bool
    is_active: bool
    is_enabled: bool
    is_consistent: bool

    def __init__(self) -> None:
        self.is_nginx_active = get_service_status("nginx", "is-active")
        self.is_backend_active = get_service_status("backend", "is-active")
        self.is_nginx_enabled = get_service_status("nginx", "is-enabled")
        self.is_backend_enabled = get_service_status("backend", "is-enabled")
        self.is_certificate_service_enabled = get_service_status("certificate", "is-enabled")
        self.is_active = self.is_nginx_active and self.is_backend_active
        self.is_enabled = self.is_nginx_enabled and self.is_backend_enabled and self.is_certificate_service_enabled
        self.is_consistent = len(set([self.is_nginx_active, self.is_backend_active, self.is_nginx_enabled,
                                      self.is_backend_enabled, self.is_certificate_service_enabled])) == 1


def find_server_config_by_listen(server_config: nginx.Conf, listen_value: str) -> Optional[nginx.Server]:
    for server in server_config.filter("Server"):
        listen_key = server.filter("Key", "listen")
        if not listen_key:
            return None
        listen_key = listen_key[0].as_list[1].split()
        if listen_value in listen_key:
            return server
    return None


def remove_server_from_config(server_config: nginx.Conf, server: nginx.Server) -> None:
    if server in server_config.filter("Server"):
        server_config.remove(server)


def add_new_server(server_config: nginx.Conf, list_of_keys: Union[nginx.Key, nginx.Location]) -> None:
    server = nginx.Server()
    for key in list_of_keys:
        server.add(key)
    server_config.add(server)


def get_listen_port(server: nginx.Server) -> Optional[str]:
    listen_key = server.filter("Key", "listen")
    if not listen_key:
        return None
    #  In nignix config listen can have following syntax
    #  listen address[:port]
    #  listen port
    #  listen unix:path
    #  Last case with unix:path is no supported
    listen_port: str = listen_key[0].as_list[1].split(" ")[0].split(":")[-1]
    return listen_port


def get_server_port() -> Optional[int]:
    nginx_conf = nginx_config.read_text()
    port_pattern = r'listen\s+(\d+)\s+ssl;'
    match = re.search(port_pattern, nginx_conf)
    if match:
        port_value = match.group(1)
        return int(port_value)
    else:
        return None


#  Since mgmtd-webgui is running as mgmtd user we need to set
#  proper owner to www-data for ngnix to be able to access it
#  in addition we add ACL to make sure that our mgmtd-webgui
#  can modify this file in future
def fix_server_config_permission(config_path: Path) -> None:
    run_command(f"pkexec /bin/chown www-data:www-data {str(config_path)}")
    run_command(f"pkexec setfacl -m u:mgmtd:rwx,mask:rw- {str(config_path)}")


def enable_or_disable_wegui(user_data: Dict[str, str]) -> None:
    action = get_bool(user_data, "is_enabled")
    for service in "certificate", "nginx", "backend":
        is_enabled = get_service_status(service, "is-enabled")
        if action and not is_enabled:
            run_command(f"systemctl enable --now {service}")
        if not action and is_enabled:
            run_command(f"systemctl disable --now {service}")


def manage_service(message: bytes) -> None:
    config = get_dict(json.loads(message), 'webgui')
    enable_or_disable_wegui(config)


def set_config(message: bytes) -> None:
    config = get_dict(json.loads(message), 'webgui')
    if config.get("port") is not None:
        modify_port(config)

    if config.get("is_enabled") is not None:
        enable_or_disable_wegui(config)

    if config.get("http_redirect") is not None:
        modify_redirect(config)


def get_gui_config(message: bytes) -> Mapping[str, Any]:
    expect_empty_message(message, "get_gui_config()")
    statuses = ServiceStatus()
    subservice_status = "OK" if statuses.is_consistent else f"WARNING: not all services running as expected: {statuses}"
    server_config = nginx.loadf(nginx_config)
    http_redirect = http_redirect_status(server_config)
    output = {'webgui':
              {"is_running": statuses.is_active,
               "is_enabled": statuses.is_enabled,
               "http_redirect": http_redirect,
               "subservice_status": subservice_status,
               "port": get_server_port()}}
    if not statuses.is_consistent:
        logger.warning("WebGUI state is inconsistent")
        logger.warning(f"{statuses}")
    return output


def modify_port(user_data: Dict[str, str]) -> None:
    ssl_port = get_int(user_data, "port")
    if ssl_port < 1 or ssl_port > 65535:
        raise InvalidParameterError("The port number has to be in range 1-65535")
    is_nginx_enabled = get_service_status("nginx", "is-active")
    server_config = nginx.loadf(nginx_config)
    #  Update SSL part
    https_server: nginx.Server = find_server_config_by_listen(server_config, "ssl")
    listen_key = https_server.filter("Key", "listen")
    new_listen = nginx.Key('listen', f'{ssl_port} ssl')
    https_server.remove(listen_key[0])
    https_server.add(new_listen)
    # Update http redirect if exists
    http_server = find_server_config_by_listen(server_config, "80")
    if http_server:
        #  Remove redirect to old port
        remove_server_from_config(server_config, http_server)
        location = nginx.Location('/', nginx.Key('return', f'301 https://$host:{ssl_port}$request_uri'))
        add_new_server(server_config, [nginx.Key('listen', '80'), location])
    nginx.dumpf(server_config, nginx_config)
    fix_server_config_permission(nginx_config)
    if is_nginx_enabled:
        run_command("systemctl restart nginx")


def change_gui_port(message: bytes) -> None:
    config = get_dict(json.loads(message), 'webgui')
    modify_port(config)


def modify_redirect(user_data: Dict[str, str]) -> None:
    action = get_bool(user_data, "http_redirect")
    nginx_status = get_service_status("nginx", "is-active")
    server_config = nginx.loadf(nginx_config)
    http_server = find_server_config_by_listen(server_config, "80")
    if not action and http_server is None:
        logger.info('modify_redirect() Redirect is already disabled')
        return
    if action and http_server is not None:
        logger.info('modify_redirect() Redirect is already enabled')
        return
    if action and http_server is None:
        ssl_server = find_server_config_by_listen(server_config, "ssl")
        ssl_port = get_listen_port(ssl_server)
        location = nginx.Location('/', nginx.Key('return', f'301 https://$host:{ssl_port}$request_uri'))
        add_new_server(server_config, [nginx.Key('listen', '80'), location])
    if not action and http_server is not None:
        remove_server_from_config(server_config, http_server)
    nginx.dumpf(server_config, nginx_config)
    fix_server_config_permission(nginx_config)
    if nginx_status:
        run_command("systemctl restart nginx")


def manage_redirect(message: bytes) -> None:
    config = get_dict(json.loads(message), 'webgui')
    modify_redirect(config)


def http_redirect_status(server_config: nginx.Server) -> bool:
    http_server = find_server_config_by_listen(server_config, "80")
    return True if http_server else False


def main() -> None:
    _parser = argparse.ArgumentParser(prog='Webgui config daemon')
    com_client.add_command_line_params(_parser)
    _args = _parser.parse_args()
    _client = com_client.Client(args=_args)
    messages = {}
    messages[topics.webgui.manage_service] = guarded(sync(manage_service))
    messages[topics.webgui.change_port] = guarded(sync(change_gui_port))
    messages[topics.webgui.set_config] = guarded(sync(set_config))
    messages[topics.webgui.get_config] = guarded(sync(get_gui_config))
    messages[topics.webgui.manage_redirect] = guarded(sync(manage_redirect))
    _client.register_responders(messages)

    while True:
        try:
            _client.wait_and_receive()
        except _client.LostRequestList as lre:
            logger.warning(f"Received LostRequestList: {lre}")
        except _client.ConnectionResetError as cre:
            logger.warning(f"Received ConnectionResetError: {cre}")


if __name__ == "__main__":
    main()
