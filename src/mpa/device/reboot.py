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

import re
from datetime import datetime, timezone

from mpa.communication.common import RebootError, expect_empty_message
from mpa.communication.process import run_command


def reboot_time_left() -> float | None:
    """Return the number of seconds left until the scheduled reboot, or None if no reboot is scheduled."""
    # output is on stderr and return code should be 0
    p = run_command("systemctl reboot --when=show")
    stderr = p.stderr.decode().strip()
    reboot_time = _parse_reboot_time(stderr)
    return _reboot_time_left(reboot_time) if reboot_time else None


def reboot_device(msg: bytes = b"") -> None:
    """Schedule a system reboot."""
    expect_empty_message(msg, "reboot_device")
    run_command("pkexec /usr/sbin/eg_reboot")
    reboot_time = reboot_time_left()
    if reboot_time is None:
        raise RebootError("Failed to schedule reboot")


def _parse_reboot_time(string: str) -> datetime | None:
    # No scheduled shutdown.
    # OR
    # Reboot scheduled for Fri 2026-10-09 10:20:55 UTC, use 'systemctl reboot --when=cancel' to cancel.
    if string.startswith("No scheduled shutdown."):
        return None

    m = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", string)
    if m is None:
        raise RebootError(f"Unexpected output: {string}")

    return datetime.strptime(m.group(), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)


def _reboot_time_left(reboot_time: datetime) -> float:
    now = datetime.now(timezone.utc)
    return max(0.0, (reboot_time - now).total_seconds())
