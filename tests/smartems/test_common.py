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

import os

import pytest

from mpa.communication.common import InvalidImageFeaturesError, InvalidVersionError, SWUpdateError
from mpa.smartems.common import (
    AbruptedCommandError,
    CommandError,
    CommandStatus,
    DeviceContext,
    ErrorCategory,
    FirmwareDownloadError,
    FirmwareNoSpaceError,
    InvalidFirmwareError,
    SmartEmsError,
    fill_with_error,
)


class TestDeviceContext:
    def test_to_dict(self) -> None:
        ctx = DeviceContext(
            serial_number="SN123",
            firmware_version="1.0.0",
            hardware_version="hw1",
            registration_id="reg1",
            endorsement_key="key1",
            boot_time=1234567890,
        )
        assert ctx.to_dict() == {
            "serialNumber": "SN123",
            "firmwareVersion": "1.0.0",
            "hardwareVersion": "hw1",
            "registrationId": "reg1",
            "endorsementKey": "key1",
            "bootTime": 1234567890,
        }

    def test_is_frozen(self) -> None:
        ctx = DeviceContext(
            serial_number="SN123",
            firmware_version="1.0.0",
            hardware_version="hw1",
            registration_id="reg1",
            endorsement_key="key1",
            boot_time=1234567890,
        )
        with pytest.raises(AttributeError):
            ctx.serial_number = "changed"


class TestCommandError:
    def test_build_error_contents(self) -> None:
        result = CommandError("something failed", ErrorCategory.GENERALERROR).to_dict()

        assert result == {
            "commandStatus": CommandStatus.ERROR.value,
            "commandStatusErrorMessage": "something failed",
            "commandStatusErrorCategory": ErrorCategory.GENERALERROR.value,
            "commandStatusErrorPid": os.getpid(),
        }

    @pytest.mark.parametrize("category", list(ErrorCategory))
    def test_build_error_all_categories(self, category: ErrorCategory) -> None:
        result = CommandError("msg", category).to_dict()
        assert result["commandStatusErrorCategory"] == category.value


class TestFillWithError:
    @pytest.mark.parametrize(
        ("exception", "expected_category"),
        [
            (AbruptedCommandError("aborted"), ErrorCategory.ABRUPTEDCOMMAND),
            (FirmwareNoSpaceError("no space"), ErrorCategory.NOSPACE),
            (FirmwareDownloadError("download failed"), ErrorCategory.DOWNLOADERROR),
            (InvalidFirmwareError("bad fw"), ErrorCategory.BADFIRMWARE),
            (InvalidVersionError("bad version"), ErrorCategory.BADFIRMWARE),
            (InvalidImageFeaturesError("bad features"), ErrorCategory.BADFIRMWARE),
            (SWUpdateError("update failed"), ErrorCategory.BADFIRMWARE),
        ],
    )
    def test_fill_with_error_known_types(
        self, exception: Exception, expected_category: ErrorCategory
    ) -> None:
        data: dict = {"existing": "value"}
        result = fill_with_error(data, exception)

        assert result["existing"] == "value"
        assert result["commandStatus"] == CommandStatus.ERROR.value
        assert result["commandStatusErrorMessage"] == str(exception)
        assert result["commandStatusErrorCategory"] == expected_category.value
        assert result is data

    def test_fill_with_error_unknown_type_defaults_to_general(self) -> None:
        data: dict = {}
        result = fill_with_error(data, ValueError("random error"))

        assert result["commandStatusErrorCategory"] == ErrorCategory.GENERALERROR.value
        assert result["commandStatusErrorMessage"] == "random error"

    def test_fill_with_error_smartems_base_error_defaults_to_general(self) -> None:
        data: dict = {}
        result = fill_with_error(data, SmartEmsError("generic smartems error"))

        assert result["commandStatusErrorCategory"] == ErrorCategory.GENERALERROR.value

    def test_fill_with_error_updates_in_place(self) -> None:
        data = {"foo": "bar"}
        returned = fill_with_error(data, AbruptedCommandError("x"))
        assert returned is data
        assert "foo" in returned
