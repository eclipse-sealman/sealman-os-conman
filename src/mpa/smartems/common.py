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
import os
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from mpa.communication.common import InvalidVersionError, InvalidImageFeaturesError, SWUpdateError


class SmartEmsError(Exception):
    ...


class AbruptedCommandError(SmartEmsError):
    ...


class FirmwareDownloadError(SmartEmsError):
    ...


class FirmwareNoSpaceError(SmartEmsError):
    ...


class InvalidFirmwareError(SmartEmsError):
    ...


class SystemUpdateError(SmartEmsError):
    ...


class CommandStatus(StrEnum):
    SUCCESS = "success"
    ERROR = "error"


class CommandName(StrEnum):
    GET_CONFIG = "get_config"
    UPDATE_CONFIG = "update_config"
    UPDATE_FIRMWARE = "update_firmware"
    REBOOT = "reboot"


class ErrorCategory(StrEnum):
    BADFIRMWARE = "badfirmware"
    NOSPACE = "nospace"
    DOWNLOADERROR = "downloaderror"
    GENERALERROR = "generalerror"
    ABRUPTEDCOMMAND = "abruptedcommand"
    SYSTEMUPDATEFAILURE = "systemupdatefailure"


@dataclass(frozen=True)
class DeviceContext:
    serial_number: str
    firmware_version: str
    hardware_version: str
    registration_id: str
    endorsement_key: str
    boot_time: int

    def to_dict(self) -> dict[str, str | int]:
        return {
            "serialNumber": self.serial_number,
            "firmwareVersion": self.firmware_version,
            "hardwareVersion": self.hardware_version,
            "registrationId": self.registration_id,
            "endorsementKey": self.endorsement_key,
            "bootTime": self.boot_time,
        }


@dataclass(frozen=True)
class CommandError:
    message: str
    category: ErrorCategory
    pid: int = field(default_factory=os.getpid)

    def to_dict(self) -> dict[str, str | int]:
        return {
            "commandStatus": CommandStatus.ERROR.value,
            "commandStatusErrorMessage": self.message,
            "commandStatusErrorCategory": self.category.value,
            "commandStatusErrorPid": self.pid,
        }


def fill_with_error(data: dict[str, Any], error: Exception) -> dict[str, Any]:
    category = {
        AbruptedCommandError: ErrorCategory.ABRUPTEDCOMMAND,
        FirmwareNoSpaceError: ErrorCategory.NOSPACE,
        FirmwareDownloadError: ErrorCategory.DOWNLOADERROR,
        InvalidFirmwareError: ErrorCategory.BADFIRMWARE,
        InvalidVersionError: ErrorCategory.BADFIRMWARE,
        InvalidImageFeaturesError: ErrorCategory.BADFIRMWARE,
        SWUpdateError: ErrorCategory.BADFIRMWARE,
        SystemUpdateError: ErrorCategory.SYSTEMUPDATEFAILURE,
    }.get(type(error), ErrorCategory.GENERALERROR)

    data.update(**CommandError(str(error), category).to_dict())
    return data
