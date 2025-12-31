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
# The main goal of this daemon is to minimize amount of code running with root privilege

# Standard imports
import json
import logging
import sys
from typing import Any, Dict

# Local imports
from mpa.common.common import RESPONSE_FAILURE, RESPONSE_OK
from mpa.common.logger import Logger
from mpa.communication.message_parser import get_dict, get_int, get_str
from mpa.device.common import (
    SOCKET_RETURN_TYPE,
    SSH_SOCKET_PATH,
    AuthorizedKeys,
    SshAction,
)
from mpa.device.socket_daemon import SocketDaemon

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")


class SSHSocketDaemon(SocketDaemon):
    def __init__(self, logger: logging.Logger) -> None:
        super().__init__(SSH_SOCKET_PATH, logger)

    def handle_message(self, message: bytes) -> SOCKET_RETURN_TYPE:
        decoded_message = json.loads(message)
        action = get_str(decoded_message, "action")
        response: Dict[str, Any] = {"status": RESPONSE_OK}
        match action:
            case SshAction.ADD:
                username = get_str(decoded_message, "username")
                key = get_str(decoded_message, "key")
                AuthorizedKeys(username).add_ssh_key(key)
            case SshAction.SHOW:
                username = get_str(decoded_message, "username")
                response["keys"] = {username: AuthorizedKeys(username).read_ssh_keys()}
            case SshAction.REMOVE:
                username = get_str(decoded_message, "username")
                index = get_int(decoded_message, "index")
                AuthorizedKeys(username).delete_ssh_key(index)
            case SshAction.GET_ALL:
                keys, statuses = AuthorizedKeys.get_all_keys()
                response["keys"] = keys
                response["user_status"] = statuses
            case SshAction.SET_ALL:
                incoming_keys = get_dict(decoded_message, "data")
                user_status = {}
                for user, user_keys in incoming_keys.items():
                    try:
                        AuthorizedKeys(user).replace_ssh_keys_of_user(user_keys)
                        user_status[user] = RESPONSE_OK
                    except Exception as ex:
                        user_status[user] = f"{RESPONSE_FAILURE} {str(ex)}"
                response["user_status"] = user_status
            case _:
                raise RuntimeError(
                    f"Unrecognized action '{action}' received by ssh key management subsystem"
                )
        return response


def main() -> None:
    ssh_socket_daemon = SSHSocketDaemon(logger)
    ssh_socket_daemon.run()


if __name__ == "__main__":
    main()
