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
Common configuration constants
"""

# Standard imports
from pathlib import Path

CONFIG_DIR_ROOT = Path("/etc")
SYSTEMD_ROOT = Path("/lib/systemd")
CONFIG_FORMAT_VERSION_TO_ASSUME_FOR_UNVERSIONED_CONFIG = "0.1"
CONFIG_FORMAT_VERSION = "1.0"
AZURE_CONFIG_VALIDATED_PATH = CONFIG_DIR_ROOT / "eg/azure_config_validated"
