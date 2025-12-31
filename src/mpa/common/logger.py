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

# Standard imports
import logging

# Third party imports
from systemd.journal import JournalHandler  # type: ignore


def Logger(name: str, identifier: str = "eg") -> logging.Logger:
    """[summary]

    Args:
        name (str): [description]
        identifier (str, optional): [description]. Defaults to "eg".

    Returns:
        logging.Logger: [description]
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(JournalHandler(APPLICATION_NAME=f"{name}", SYSLOG_IDENTIFIER=f"{identifier}: {name}", SYSLOG_FACILITY=22))
    return logger
