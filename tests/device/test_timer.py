#
# Copyright (c) 2026 Contributors to the Eclipse Foundation.
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
from unittest.mock import call, patch

import pytest

from mpa.device.timer import update_timer

TIMER_TEMPLATE = "[Timer]\nOnUnitActiveSec={interval}s\n"


class TestUpdateTimer:
    def test_writes_timer_reloads_and_restarts_it(self, tmp_path: Path) -> None:
        timer = tmp_path / "foo.timer"
        timer.write_text("")
        with patch("mpa.device.timer.run_command") as run_command:
            update_timer(interval=42, timer=timer, timer_template=TIMER_TEMPLATE)

        assert timer.read_text() == "[Timer]\nOnUnitActiveSec=42s\n"
        # restart has to come after daemon-reload, otherwise the old schedule would be applied
        assert run_command.call_args_list[-2:] == [call("systemctl daemon-reload"), call("systemctl restart foo.timer")]

    def test_missing_timer_raises_without_touching_systemd(self, tmp_path: Path) -> None:
        with patch("mpa.device.timer.run_command") as run_command:
            with pytest.raises(FileNotFoundError):
                update_timer(interval=42, timer=tmp_path / "foo.timer", timer_template=TIMER_TEMPLATE)

        run_command.assert_not_called()
