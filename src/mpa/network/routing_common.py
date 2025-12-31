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
"""This module contains common variables for routing submodule."""

# Local imports
from mpa.config.common import CONFIG_DIR_ROOT

ETHs = {"lan1", "lan2"}

# Paths
ROUTE_DIR = CONFIG_DIR_ROOT / "routes"
LOCK_FILE = ROUTE_DIR / "lock"
PRESETS = ROUTE_DIR / "presets"
EDITS = ROUTE_DIR / "edits"
ENABLED = ROUTE_DIR / "enabled"
CURRENT = ROUTE_DIR / "current"
PREVIOUS = ROUTE_DIR / "previous"
RESCUE = ROUTE_DIR / "rescue"
PRESETS_BACKUP = ROUTE_DIR / "presets_backup"
EDITS_BACKUP = ROUTE_DIR / "edits_backup"

# Common strings
INITIALLY_CREATED_AS = "Initially created as "
