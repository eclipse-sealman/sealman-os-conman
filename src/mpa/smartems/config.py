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
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit

from mpa.config.configfiles import ConfigFiles
from mpa.device.timer import update_timer

SMARTEMS_TIMER_TEMPLATE = """[Unit]
Description=Smart EMS Update timer
Documentation=

[Timer]
OnBootSec=180s
AccuracySec=1
{comment}OnCalendar=daily
{comment}OnUnitActiveSec={{interval}}s
Persistent=true

# Unused for generator unit, left in case we switch to normal one
[Install]
WantedBy=timers.target
"""

config_files = ConfigFiles()
SMARTEMS_CONFIG = config_files.add("smartems_config", "smartems/config.cfg")
SMARTEMS_CERT = config_files.add("smartems_cert", "smartems/custom.pem", is_expected=False)
SMARTEMS_TIMER = config_files.add("smartems_timer", "eg/units/smartems.timer")
config_files.verify()


class SmartEmsConfig:
    def __init__(
        self,
        username: str,
        password: str,
        url: str,
        edgegatewayvcc: bool = False,
        skip_ssl_verification: bool = False,
    ) -> None:
        self.username = username
        self.password = password
        self.url = url
        self.edgegatewayvcc = edgegatewayvcc
        self.skip_ssl_verification = skip_ssl_verification

    @staticmethod
    def get_base_url(url: str) -> str:
        """Return the base URL with HTTPS scheme and netloc only."""
        u = urlsplit(url)
        split_result = SplitResult(scheme="https", netloc=u.netloc, path="", query="", fragment="")
        return split_result.geturl()

    def get_url(self) -> str:
        return self.get_base_url(self.url) + self.endpoint

    @property
    def endpoint(self) -> str:
        return f"/api/edgegateway{'vcc' if self.edgegatewayvcc else ''}/configuration"

    @staticmethod
    def get_certificate_content() -> str:
        return SMARTEMS_CERT.read_text().strip() if SMARTEMS_CERT.exists() else ""

    @staticmethod
    def remove_certificate() -> None:
        SMARTEMS_CERT.unlink(missing_ok=True)

    @staticmethod
    def save_certificate_content(content: str) -> None:
        if content:
            SMARTEMS_CERT.write_text(content)

    def get_cert_status(self, debug_mode: bool = False) -> bool | str:
        verify: bool | str = True
        if debug_mode or self.skip_ssl_verification:
            verify = False
        elif SMARTEMS_CERT.exists():
            verify = str(SMARTEMS_CERT)
        return verify

    def get_polling_interval(self) -> int:
        for line in SMARTEMS_TIMER.read_text().strip().splitlines():
            if line.startswith("OnUnitActiveSec="):
                return int(line.split("=")[1].rstrip("s"))
        return 0

    # TODO: switch to ACL approach instead of chmod (this function was created before we introduced ACL's
    def update_timer(self, interval: int) -> None:
        if interval != 0 and interval < 10:
            raise ValueError(
                f"The value for polling interval is too low: {interval}s. Use 0 for single boot check or minimum 10s."
            )
        template = SMARTEMS_TIMER_TEMPLATE.format(comment="#" if interval == 0 else "")
        update_timer(interval=interval, timer=SMARTEMS_TIMER, timer_template=template)

    def update(self, other: SmartEmsConfig) -> None:
        self.username = other.username
        self.password = other.password
        self.url = other.url
        self.edgegatewayvcc = other.edgegatewayvcc
        self.skip_ssl_verification = other.skip_ssl_verification

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SmartEmsConfig:
        return cls(
            username=data.get("username", ""),
            password=data.get("password", ""),
            url=data.get("url", ""),
            edgegatewayvcc=data.get("edgegatewayvcc", False),
            skip_ssl_verification=data.get("skip_ssl_verification", False),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "password": self.password,
            "url": self.url,
            "edgegatewayvcc": self.edgegatewayvcc,
            "skip_ssl_verification": self.skip_ssl_verification,
        }

    def to_file(self, file_path: Path) -> None:
        file_path.write_text(json.dumps(self.to_dict()))

    @classmethod
    def from_file(cls, file_path: Path) -> SmartEmsConfig:
        return cls.from_dict(json.loads(file_path.read_text()))

    @classmethod
    def load(cls, debug_mode: bool = False) -> SmartEmsConfig:
        try:
            return cls.from_file(SMARTEMS_CONFIG)
        except Exception as e:
            if debug_mode:
                raise e

            return cls.from_dict({})

    def save(self) -> None:
        self.to_file(SMARTEMS_CONFIG)
