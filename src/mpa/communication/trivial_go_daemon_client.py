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
Python client for the GO daemon unix socket.
"""
import json
import socket
import struct
from pathlib import Path
from typing import Any

from mpa.communication.message_parser import get_optional_dict
from mpa.device.common import read_exactly


def send_to_go_daemon(
        socket_path: str | Path,
        msg_type: str,
        body: dict[str, Any] | None = None,
        timeout: float | None = None
    ) -> dict[str, Any] | None:
    """Connect to GO daemon, send length-prefixed JSON request, read response."""
    request: dict[str, Any] = {"type": msg_type}
    if body is not None:
        request["body"] = body

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(str(socket_path))
        payload = json.dumps(request).encode("utf-8")
        sock.sendall(struct.pack(">I", len(payload)))
        sock.sendall(payload)
        response_size = struct.unpack(">I", read_exactly(sock, 4))[0]
        response_payload = read_exactly(sock, response_size)

    response: dict[str, Any] = json.loads(response_payload)
    if response.get("status") != "OK":
        error_msg = response.get("exception", "Unknown error from daemon")
        raise RuntimeError(f"daemon error: {error_msg}")

    return get_optional_dict(response, "body")
