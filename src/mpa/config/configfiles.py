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
from typing import Union

# Third party imports
from packaging.version import Version

# Local imports
from mpa.common.logger import Logger
from mpa.config.common import CONFIG_DIR_ROOT
from mpa.config.common import CONFIG_FORMAT_VERSION
from mpa.config.common import CONFIG_FORMAT_VERSION_TO_ASSUME_FOR_UNVERSIONED_CONFIG

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")


class ConfigFiles(dict[str, tuple[Path, bool]]):
    def __init__(self) -> None:
        super().__init__()
        self.first_incompatible_config_format_version = Version(CONFIG_FORMAT_VERSION_TO_ASSUME_FOR_UNVERSIONED_CONFIG)

    def add(self, name: str, path: Union[str, Path], *,
            config_dir_root: Path = CONFIG_DIR_ROOT,
            is_expected: bool = True) -> Path:
        if name in self:
            raise ValueError(f"config file {name} already added")
        path = config_dir_root / path
        self[name] = (path, is_expected)
        return path

    def set_first_incompatible_config_format_version(self, version: str) -> None:
        self.first_incompatible_config_format_version = Version(version)

    def is_debug_mode_enabled(self) -> bool:
        if 'debug_mode' not in self:
            self.add("debug_mode", "debug_enable", is_expected=False)
        assert isinstance(self["debug_mode"][0], Path)
        return self["debug_mode"][0].exists()

    def verify(self) -> None:
        missing_file = False
        # Normally we will just log missing files (so in case not everything is
        # missing some functionality will be still retained), but in debug mode
        # we will throw exception and prevent daemon from starting (with
        # intention of adding debug mode to our test env for early detection of
        # missing files).
        for name, (path, is_expected) in self.items():
            if is_expected and not path.exists():
                missing_file = True
                logger.error(f"Missing config path for {name}: {path}")
        if self.is_debug_mode_enabled():
            if Version(CONFIG_FORMAT_VERSION) >= self.first_incompatible_config_format_version:
                default = Version(CONFIG_FORMAT_VERSION_TO_ASSUME_FOR_UNVERSIONED_CONFIG)
                if default != self.first_incompatible_config_format_version:
                    raise RuntimeError("Config format versioning has not been properly updated")
            if missing_file and self.is_debug_mode_enabled():
                raise RuntimeError("Expected config files missing in debug mode")
