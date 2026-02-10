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
Python client for the GO wifi daemon unix socket.
"""
from __future__ import annotations

import json
import socket
import struct
import sys
from typing import Any

from mpa.common.logger import Logger
from mpa.device.common import read_exactly

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")

WIFI_DAEMON_SOCKET = "/run/mgmtd/wifi_daemon"
WIFI_DAEMON_TIMEOUT = 10


def _send_to_wifi_daemon(msg_type: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Connect to GO wifi daemon, send length-prefixed JSON request, read response."""
    request: dict[str, Any] = {"type": msg_type}
    if body is not None:
        request["body"] = body
    payload = json.dumps(request).encode("utf-8")
    logger.info(f'_send_to_wifi_daemon() {payload=}')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(WIFI_DAEMON_TIMEOUT)
        sock.connect(WIFI_DAEMON_SOCKET)
        sock.sendall(struct.pack(">I", len(payload)))
        sock.sendall(payload)
        response_size = struct.unpack(">I", read_exactly(sock, 4))[0]
        response_payload = read_exactly(sock, response_size)

    response: dict[str, Any] = json.loads(response_payload)
    if response.get("status") != "OK":
        error_msg = response.get("exception", "Unknown error from wifi daemon")
        raise RuntimeError(f"WiFi daemon error: {error_msg}")
    return response


def daemon_ap_set_config(ap_config: dict[str, Any], is_enabled: bool = True) -> str:
    """Send set_config to GO daemon."""
    _send_to_wifi_daemon("set_config", ap_config['wifi1'])
    return "OK AP configured via daemon"


def daemon_ap_enable() -> str:
    """Tell the GO daemon to enable (re-activate) the existing AP profile."""
    _send_to_wifi_daemon("change_state", {"is_enabled": True})
    return "OK AP enabled via daemon"


def daemon_ap_disable() -> str:
    """Tell the GO daemon to disable the AP."""
    _send_to_wifi_daemon("change_state", {"is_enabled": False})
    return "OK AP disabled via daemon"


def daemon_ap_get_config() -> dict[str, Any] | None:
    """Get current AP config from GO daemon. Returns None if no AP profile exists."""
    try:
        response = _send_to_wifi_daemon("get_config")
        logger.info(f'daemon_ap_get_config() {response=}')
        return response.get("body")
    except (RuntimeError, OSError):
        return None
