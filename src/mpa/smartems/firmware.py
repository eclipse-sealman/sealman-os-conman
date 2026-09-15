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
from pathlib import Path
from typing import Any

import libarchive  # type: ignore
import libconf  # type: ignore

from .common import InvalidFirmwareError


def inspect_firmware(firmware_file: Path) -> dict[str, Any]:
    sw_description = "sw-description"
    if not firmware_file.exists():
        raise InvalidFirmwareError(f"Firmware file does not exist: {firmware_file}")

    if not firmware_file.is_file():
        raise InvalidFirmwareError(f"Firmware path is not a file: {firmware_file}")

    try:
        with libarchive.SeekableArchive(str(firmware_file)) as archive:
            description = archive.read(sw_description)
    except Exception as exc:
        raise InvalidFirmwareError(f"Unable to read {sw_description!r} from firmware image: {exc}") from exc

    try:
        config = libconf.loads(description.decode())
    except Exception as exc:
        raise InvalidFirmwareError(f"Unable to parse {sw_description!r}: {exc}") from exc

    # config is libconf.AttrDict which is a subclass of dict
    assert isinstance(config, dict)
    return parse_firmware_metadata(config)


def parse_firmware_metadata(config: dict[str, Any]) -> dict[str, Any]:
    # {
    #     'software': {
    #         'version': '1.0',
    #         'hardware-compatibility': ['eg600'],
    #         'reboot': False,
    #         'images': {
    #             'filename': '...', 'type': 'archive', 'device': '/dev/update',
    #             'compressed': 'zlib', 'filesystem': 'ext4', 'path': '/', 'preserve-attributes': True, 'sha256': '...'
    #         },
    #         'scripts': (
    #             {'filename': 'check_os_version.py', 'type': 'preinstall', 'data': '', 'sha256': '...'},
    #             {'filename': 'sw-update-script.sh', 'type': 'shellscript', 'data': '1.9.3-20260921_2014', 'sha256': '...'},
    #         )
    #     }
    # }
    version_script = "sw-update-script.sh"
    gui_support_script = "check_os_version.py"
    script_data: dict[str, list[Any]] = {version_script: [], gui_support_script: []}

    scripts = config.get("software", {}).get("scripts", ())
    for script in scripts:
        filename = script.get("filename")
        if filename in script_data:
            script_data[filename].append(script.get("data"))

    errors = []
    for name, data_values in script_data.items():
        if not data_values:
            errors.append(f"{name} is missing")
        elif len(data_values) > 1:
            errors.append(f"too many {name} scripts (found {len(data_values)})")

    version = None
    gui_support_string = None

    if len(script_data[version_script]) == 1:
        version = script_data[version_script][0]
        if not isinstance(version, str):
            errors.append(
                f"Invalid firmware version: expected a string in "
                f"'{version_script}' data, got {type(version).__name__}"
            )
        elif not version.strip():
            errors.append(f"Invalid firmware version: '{version_script}' data is empty")

    if len(script_data[gui_support_script]) == 1:
        gui_support_string = script_data[gui_support_script][0]
        if not isinstance(gui_support_string, str):
            errors.append(
                f"Invalid GUI support information: expected a string in "
                f"'{gui_support_script}' data, got {type(gui_support_string).__name__}"
            )

    if errors:
        raise InvalidFirmwareError("Invalid firmware metadata: " + "; ".join(errors))

    return {"os_version": version, "with_gui_support": gui_support_string == "WITH_GUI_SUPPORT"}
