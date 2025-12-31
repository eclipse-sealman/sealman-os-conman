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
import re
import sys
from pathlib import Path

# Local imports
from mpa.common.common import RESPONSE_OK
from mpa.common.logger import Logger
from mpa.communication.message_parser import get_list
from mpa.device.common import SHADOW_SOCKET_PATH, SOCKET_RETURN_TYPE, get_user_list
from mpa.device.socket_daemon import SocketDaemon

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")


class ShadowSocketDaemon(SocketDaemon):
    SHADOW_FILE = Path("/etc/shadow")

    def __init__(self, logger: logging.Logger) -> None:
        super().__init__(SHADOW_SOCKET_PATH, logger)

    def show(self) -> SOCKET_RETURN_TYPE:
        users: list[dict[str, str]] = get_list(get_user_list(), "users")
        user_names: list[str] = [user["name"] for user in users]
        user_password_hashes = dict(
            re.findall(
                fr"^({'|'.join(user_names)}):([^:]+)",
                self.SHADOW_FILE.read_text(),
                flags=re.MULTILINE,
            )
        )
        response = {"status": RESPONSE_OK, "user_password_hashes": user_password_hashes}
        return response

    def set_config(self, message: bytes) -> SOCKET_RETURN_TYPE:
        # TODO we only change the hashes now; do we want to change last password change?
        user_password_hashes = json.loads(message)
        shadow_content = self.SHADOW_FILE.read_text()
        for username, password_hash in user_password_hashes.items():
            shadow_content = re.sub(
                fr"(?<=^{username}:)[^:]+",
                password_hash,
                shadow_content,
                flags=re.MULTILINE,
            )

        self.SHADOW_FILE.write_text(shadow_content)
        return {"status": RESPONSE_OK}

    def handle_message(self, message: bytes) -> SOCKET_RETURN_TYPE:
        if len(message) > 0:
            return self.set_config(message)

        return self.show()


def main() -> None:
    shadow_socket_daemon = ShadowSocketDaemon(logger)
    shadow_socket_daemon.run()


if __name__ == "__main__":
    main()
