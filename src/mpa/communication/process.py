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
"""
Simple logging wrappers over shell command execution.
"""
from __future__ import annotations

# Standard imports
import shlex
import subprocess
import logging
from typing import Any

# Local imports
from mpa.common.logger import Logger

_logger = Logger(__name__)


def run_command(
    command: str, *args: Any,
    logger: logging.Logger = _logger,
    capture_output: bool = True,
    is_confidential: bool = False,
    **kwargs: Any,
) -> subprocess.CompletedProcess[bytes]:
    """
    Logs command, runs it, throws on bad exit satus.
    """

    result = run_command_unchecked(
        command, *args, logger=logger, capture_output=capture_output, is_confidential=is_confidential, **kwargs
    )
    result.check_returncode()
    return result


def run_command_unchecked(
    command: str,
    *args: Any,
    logger: logging.Logger = _logger,
    capture_output: bool = True,
    is_confidential: bool = False,
    **kwargs: Any
) -> subprocess.CompletedProcess[bytes]:
    """
    Logs command and runs it.

    Beware --- caller needs to check status himself (hence _unchecked in name).
    """
    splitted_command = shlex.split(command)
    if not is_confidential:
        logger.info(f"Will execute: {(*splitted_command, *args)}")
        logger.debug(f"capture_output={capture_output}, kwargs {kwargs}")
    return subprocess.run((*splitted_command, *args), capture_output=capture_output, shell=False, **kwargs)
