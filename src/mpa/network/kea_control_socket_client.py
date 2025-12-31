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
from __future__ import annotations

# Standard imports
import json
import socket
from typing import Any


class KeaControlSocketClient:
    def __init__(self, socket_path: str = "/var/run/kea/keactrl.sock") -> None:
        self._socket_path = socket_path

    def _send_request(self, request: dict[str, Any]) -> dict[str, Any]:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(self._socket_path)
            sock.sendall(json.dumps(request).encode())
            response = self._read_response(sock)
            return response

    def _read_response(self, sock: socket.socket) -> dict[str, Any]:
        response_chunks: list[bytes] = []
        while chunk := sock.recv(4096):
            response_chunks.append(chunk)

        response = json.loads(b''.join(response_chunks).decode())
        assert isinstance(response, dict)
        return response

    def config_test(self, dhcp4_config: dict[str, Any]) -> dict[str, Any]:
        request = {
            "command": "config-test",
            "arguments": dhcp4_config
        }
        # {'result': 0, 'text': 'Configuration seems sane.
        # Control-socket, hook-libraries, and D2 configuration were sanity checked, but not applied.'}
        return self._send_request(request)

    def leases_reclaim(self) -> dict[str, Any]:
        request = {
            "command": "leases-reclaim",
            "arguments": {
                "remove": True
            }
        }
        # {'result': 0, 'text': 'Reclamation of expired leases is complete.'}
        return self._send_request(request)

    def config_get(self) -> dict[str, Any]:
        request = {
            "command": "config-get"
        }
        # {'arguments': {'Dhcp4': ...}, 'hash': 'AA4F3243C9CF1AC44857DE7CD1DDFE1B452114E2C0A0DE61DC44A893074C615A'}, 'result': 0}
        return self._send_request(request)

    def config_write(self, filename: str) -> dict[str, Any]:
        request = {
            "command": "config-write",
            "arguments": {
                "filename": filename
            }
        }
        # {'arguments': {'filename': '/etc/kea/kea-dhcp4.conf.tmp', 'size': 2551},
        # 'result': 0, 'text': 'Configuration written to /etc/kea/kea-dhcp4.conf.tmp successful'}
        return self._send_request(request)

    def config_set(self, dhcp4_config: dict[str, Any]) -> dict[str, Any]:
        request = {
            "command": "config-set",
            "arguments": dhcp4_config
        }
        # {'arguments': {'hash': 'AA4F3243C9CF1AC44857DE7CD1DDFE1B452114E2C0A0DE61DC44A893074C615A'},
        # 'result': 0, 'text': 'Configuration successful.'}
        return self._send_request(request)
