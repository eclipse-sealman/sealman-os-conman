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
Daemon for simple unix socket based exchange of messages between mgmtd owned
process and root owned process. The main goal of this daemon is to minimize
amount of code running with root privileges. Root requiring tasks are
extracted from mgmtd process to separate one, and that separate one does not
implement full forwarder based message bus, but only this trivial daemon on
separate socket.
"""

# Standard imports
import codecs
import grp
import json
import logging
import os
import pickle
import pwd
import socket
import struct
from pathlib import Path

# Local imports
from mpa.common.common import RESPONSE_FAILURE
from mpa.device.common import SOCKET_RETURN_TYPE, read_exactly


class SocketDaemon:
    def __init__(self, socket_path: Path, logger: logging.Logger) -> None:
        self.socket_path = socket_path
        self.logger = logger
        self.socket_path.unlink(missing_ok=True)

    def handle_message(self, message: bytes) -> SOCKET_RETURN_TYPE:
        """Implement this method within your socket daemon"""

        raise NotImplementedError

    def handle_client(self, client_socket: socket.socket) -> None:
        # We process one query per connection to limit possibility of getting out of
        # sync between client and server and allow restarts of server without
        # restarts of client
        try:
            # TODO how should we handle this more gracefully?
            # reading/sending data from/to the closed socket may result in a BrokenPipeError: [Errno 32] Broken pipe
            # so the timeout was increased from 1 to 2 seconds
            client_socket.settimeout(2)
            query_size = struct.unpack(">I", read_exactly(client_socket, 4))[0]
            self.logger.info(f"Received new request, incoming data size: {query_size}")
            try:
                query_payload = read_exactly(client_socket, query_size)
                response = self.handle_message(query_payload)
            except Exception as exc:
                self.logger.exception(exc)
                response = {
                    "status": RESPONSE_FAILURE,
                    "exception": codecs.encode(pickle.dumps(exc), "base64").decode(),
                }
            response_bytes = bytearray(json.dumps(response), "UTF-8")
            client_socket.sendall(struct.pack(">I", len(response_bytes)))
            client_socket.sendall(response_bytes)
        except Exception as exc:
            self.logger.exception(exc)
            raise
        finally:
            client_socket.close()

    def run(self) -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.bind(str(self.socket_path))
            os.chown(
                self.socket_path,
                pwd.getpwnam("mgmtd").pw_uid,
                grp.getgrnam("mgmtd").gr_gid,
            )
            os.chmod(self.socket_path, 0o600)
            self.logger.info(f"Started serever at {self.socket_path}")
            sock.listen()
            while True:
                connection, _ = sock.accept()
                # We don't use threads for now intentionally, becasue we want to
                # serialize key related actions
                self.handle_client(connection)
