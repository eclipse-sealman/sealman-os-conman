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
from datetime import datetime, timezone

import pytest

import mpa.device.reboot as reboot_module
from mpa.communication.common import RebootError


def test_parse_reboot_time_returns_none_when_no_shutdown_is_scheduled():
    assert reboot_module._parse_reboot_time("No scheduled shutdown.") is None


def test_parse_reboot_time_parses_utc_timestamp():
    result = reboot_module._parse_reboot_time(
        "Reboot scheduled for Fri 2026-10-09 10:20:55 UTC, use 'systemctl reboot --when=cancel' to cancel."
    )

    assert result == datetime(2026, 10, 9, 10, 20, 55, tzinfo=timezone.utc)


def test_parse_reboot_time_rejects_unexpected_output():
    with pytest.raises(RebootError, match="Unexpected output"):
        reboot_module._parse_reboot_time("Unexpected output")


@pytest.mark.parametrize(
    ("reboot_time", "expected"),
    [
        (datetime(2026, 10, 9, 10, 20, 55, tzinfo=timezone.utc), 60.0),
        (datetime(2026, 10, 9, 10, 18, 55, tzinfo=timezone.utc), 0.0),
    ],
)
def test_reboot_time_left_counts_down_and_clamps_at_zero(monkeypatch, reboot_time, expected):
    fixed_now = datetime(2026, 10, 9, 10, 19, 55, tzinfo=timezone.utc)

    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed_now

    monkeypatch.setattr(reboot_module, "datetime", FixedDateTime)
    assert reboot_module._reboot_time_left(reboot_time) == expected
