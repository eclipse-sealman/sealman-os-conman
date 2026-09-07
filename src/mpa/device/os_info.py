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
from dataclasses import dataclass


@dataclass(frozen=True)
class OsInfo:
    name: str
    version: str
    version_id: str
    pretty_name: str
    build_id: str
    pipeline_id: str
    install_timestamp: str
    with_gui_support: bool
    signed_update: bool

    @staticmethod
    def parse(s: str) -> dict[str, str]:
        lines = s.strip().splitlines()
        os_info = {}
        for line in lines:
            parts = line.strip().split("=", maxsplit=1)
            if len(parts) != 2:
                continue

            key = parts[0].lower()
            value = parts[1].strip('"')
            os_info[key] = value

        return os_info

    @classmethod
    def from_dict(cls, d: dict[str, str]) -> OsInfo:
        """
        Create an OsInfo instance from a dictionary.

        Missing keys will be filled with default values (empty string or False).
        """
        return cls(
            name=d.get("name", ""),
            version=d.get("version", ""),
            version_id=d.get("version_id", ""),
            pretty_name=d.get("pretty_name", ""),
            build_id=d.get("build_id", ""),
            pipeline_id=d.get("pipeline_id", ""),
            install_timestamp=d.get("install_timestamp", ""),
            with_gui_support=d.get("with_gui_support") == "TRUE",
            signed_update=d.get("signed_update") == "TRUE",
        )

    @classmethod
    def from_str(cls, s: str) -> OsInfo:
        return cls.from_dict(cls.parse(s))
