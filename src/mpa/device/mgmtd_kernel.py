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
from pathlib import Path

# Local imports
from mpa.common.common import RESPONSE_OK
from mpa.common.logger import Logger
from mpa.device.common import KERNEL_SOCKET_PATH, SOCKET_RETURN_TYPE
from mpa.device.socket_daemon import SocketDaemon

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")


class KernelSocketDaemon(SocketDaemon):
    def __init__(self, logger: logging.Logger) -> None:
        super().__init__(KERNEL_SOCKET_PATH, logger)

    def handle_message(self, message: bytes) -> SOCKET_RETURN_TYPE:
        decoded_message = json.loads(message)
        flag, file = decoded_message["flag"], decoded_message["file"]
        Path(file).write_text(flag)
        return {"status": RESPONSE_OK}


def main() -> None:
    kernel_socket_daemon = KernelSocketDaemon(logger)
    kernel_socket_daemon.run()


if __name__ == "__main__":
    main()
