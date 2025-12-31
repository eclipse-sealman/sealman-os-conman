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
from enum import Enum
from pathlib import Path
from typing import Iterator


from mpa.common.common import RESPONSE_FAILURE, FileExtension
from mpa.config.common import CONFIG_DIR_ROOT


class OvpnAction(Enum):
    ENABLE = "enable"
    DISABLE = "disable"
    STATUS = "status"


def get_ovpn_configs() -> Iterator[Path]:
    ovpn_configs = OVPN_CONFIG_DIR.glob(f"*{FileExtension.OVPN.value}")
    return ovpn_configs


OVPN_CONFIG_DIR = CONFIG_DIR_ROOT / "openvpn"
OVPN_CONFIG_FILE_ALREADY_EXISTS = f"{RESPONSE_FAILURE} config file for tunnel already exists and overwrite was not requested"
