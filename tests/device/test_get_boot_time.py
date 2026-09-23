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
import pytest

from mpa.device.common import get_boot_time, parse_boot_time


class TestParseBootTime:
    def test_parses_btime_value(self) -> None:
        lines = [
            "cpu  123 456\n",
            "btime 1690000000\n",
            "processes 42\n",
        ]
        assert parse_boot_time(lines) == 1690000000

    def test_parses_btime_when_first_line(self) -> None:
        lines = ["btime 1000\n"]
        assert parse_boot_time(lines) == 1000

    def test_ignores_lines_without_btime_prefix(self) -> None:
        lines = ["notbtime 999\n", "btime 55\n"]
        assert parse_boot_time(lines) == 55

    def test_raises_when_btime_missing(self) -> None:
        lines = ["cpu 1 2 3\n", "processes 42\n"]
        with pytest.raises(RuntimeError, match="Boot time not found"):
            parse_boot_time(lines)

    def test_raises_on_empty_input(self) -> None:
        with pytest.raises(RuntimeError, match="Boot time not found"):
            parse_boot_time(iter([]))


class TestGetBootTime:
    def test_reads_and_parses_proc_stat(self, tmp_path, monkeypatch) -> None:
        stat_file = tmp_path / "stat"
        stat_file.write_text("cpu 1 2\nbtime 1234567890\n")
        monkeypatch.setattr("mpa.device.common.Path", lambda _: stat_file)

        assert get_boot_time() == 1234567890
