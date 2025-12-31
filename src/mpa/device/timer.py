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
# Standard imports
import sys
from pathlib import Path

# Local imports
from mpa.common.logger import Logger
from mpa.communication.process import run_command

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")


def update_timer(interval: int, timer: Path, timer_template: str) -> None:
    if timer.exists() is False:
        raise FileNotFoundError
    if "{interval}" not in timer_template:
        raise KeyError("Missing key {interval} in timer_template")

    logger.info(f"Setting interval to {interval}")
    run_command(f"pkexec /bin/chmod 777 {timer}")
    timer_config = timer_template.format(interval=interval)
    timer.write_text(timer_config)
    run_command(f"pkexec /bin/chmod 644 {timer}")
    run_command("systemctl daemon-reload")  # reload all systemd units
