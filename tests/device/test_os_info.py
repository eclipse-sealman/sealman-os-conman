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

from mpa.device.os_info import OsInfo


class TestOsInfo:
    def test_parse(self):
        input_str = """NAME="Ubuntu"
VERSION="20.04.6 LTS (Focal Fossa)"
VERSION_ID="20.04"
PRETTY_NAME="Ubuntu 20.04.6 LTS"
BUILD_ID="20230420"
INSTALL_TIMESTAMP="2023-04-20T12:34:56Z"
WITH_GUI_SUPPORT="TRUE"
SIGNED_UPDATE="FALSE"
"""
        expected_dict = {
            "name": "Ubuntu",
            "version": "20.04.6 LTS (Focal Fossa)",
            "version_id": "20.04",
            "pretty_name": "Ubuntu 20.04.6 LTS",
            "build_id": "20230420",
            "install_timestamp": "2023-04-20T12:34:56Z",
            "with_gui_support": "TRUE",
            "signed_update": "FALSE",
        }
        assert OsInfo.parse(input_str) == expected_dict

    def test_from_dict(self):
        input_dict = {
            "name": "Ubuntu",
            "version": "20.04.6 LTS (Focal Fossa)",
            "pretty_name": "Ubuntu 20.04.6 LTS",
            "build_id": "20230420",
            "pipeline_id": "12345",
            "with_gui_support": "TRUE",
        }
        os_info = OsInfo.from_dict(input_dict)
        assert os_info.name == "Ubuntu"
        assert os_info.version == "20.04.6 LTS (Focal Fossa)"
        assert os_info.version_id == ""
        assert os_info.pretty_name == "Ubuntu 20.04.6 LTS"
        assert os_info.build_id == "20230420"
        assert os_info.pipeline_id == "12345"
        assert os_info.install_timestamp == ""
        assert os_info.with_gui_support is True
        assert os_info.signed_update is False

    @pytest.mark.parametrize(
        "input_str, expected_os_info",
        [
            (
                """NAME="Fedora"
VERSION="38 (Workstation Edition)"
PRETTY_NAME="Fedora 38 (Workstation Edition)"
BUILD_ID="20230420"
INSTALL_TIMESTAMP="2023-04-20T12:34:56Z"
WITH_GUI_SUPPORT="FALSE"
SIGNED_UPDATE="TRUE"
""",
                OsInfo(
                    name="Fedora",
                    version="38 (Workstation Edition)",
                    version_id="",
                    pretty_name="Fedora 38 (Workstation Edition)",
                    build_id="20230420",
                    pipeline_id="",
                    install_timestamp="2023-04-20T12:34:56Z",
                    with_gui_support=False,
                    signed_update=True,
                ),
            ),
            (
                "",
                OsInfo(
                    name="",
                    version="",
                    version_id="",
                    pretty_name="",
                    build_id="",
                    pipeline_id="",
                    install_timestamp="",
                    with_gui_support=False,
                    signed_update=False,
                ),
            ),
        ],
    )
    def test_from_str(self, input_str: str, expected_os_info: OsInfo) -> None:
        os_info = OsInfo.from_str(input_str)
        assert os_info == expected_os_info
