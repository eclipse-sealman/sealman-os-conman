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
from pathlib import Path
from typing import Any

from mpa.common.logger import Logger
from mpa.device.common import read_exactly
from mpa.communication.message_parser import get_optional_dict

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")

WIFI_DAEMON_SOCKET = "/run/mgmtd/wifi_daemon"
WIFI_DAEMON_TIMEOUT = 10


def is_wifi_daemon_available() -> bool:
    return Path(WIFI_DAEMON_SOCKET).exists()


def _send_to_wifi_daemon(msg_type: str, body: dict[str, Any] | None = None) -> dict[str, Any] | None:
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
    return get_optional_dict(response, "body")


def daemon_ap_set_config(ap_config: dict[str, Any]) -> str | None:
    # TODO consider flattenig also python<->go interface
    config = {"ap": ap_config['wifi1']}
    is_enabled = config['ap'].pop("is_enabled", None)
    if is_enabled is not None:
        config["is_enabled"] = is_enabled
    # TODO check exact body format and adjust if needed
    if len(config['ap']) == 0:
        config.pop('ap')
    return str(_send_to_wifi_daemon("set_config", config))


def daemon_ap_enable() -> None:
    retval = _send_to_wifi_daemon("change_state", {"is_enabled": True})
    assert retval is None


def daemon_ap_disable() -> None:
    retval = _send_to_wifi_daemon("change_state", {"is_enabled": False})
    assert retval is None


def daemon_ap_restart() -> None:
    retval = _send_to_wifi_daemon("restart", {})
    assert retval is None


def daemon_ap_get_config() -> dict[str, Any] | None:
    """Returns None if no AP profile exists."""
    try:
        response = _send_to_wifi_daemon("get_config")
        return response
    # TODO do we really wat to treat all those errors as lack of config???
    except (RuntimeError, OSError):
        return None
