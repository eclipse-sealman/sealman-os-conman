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
import os
import threading

# Local imports
from mpa.common.logger import Logger

logger = Logger(__name__)


class KillerThread(threading.Thread):
    """A thread that kills an application after an Exception is thrown"""
    def run(self) -> None:
        try:
            super().run()
        except Exception as exc:
            logger.exception(exc)
            os._exit(1)
