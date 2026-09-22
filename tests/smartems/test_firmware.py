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

from mpa.smartems.firmware import InvalidFirmwareError, parse_firmware_metadata


class TestFirmwareMetadata:
    @pytest.mark.parametrize("config, expected_version, expected_gui_support", [
        (
            {
                'software': {
                    'scripts': (
                        {'filename': 'check_os_version.py', 'data': 'WITH_GUI_SUPPORT'},
                        {'filename': 'sw-update-script.sh', 'data': '1.9.3-20260921_2014'},
                    )
                }
            },
            "1.9.3-20260921_2014",
            True
        ),
        (
            {
                'software': {
                    'scripts': (
                        {'filename': 'sw-update-script.sh', 'data': '1.10.1'},
                        {'filename': 'check_os_version.py', 'data': ''},
                    )
                }
            },
            "1.10.1",
            False
        )
    ])
    def test_parse_firmware_metadata_correct(self, config, expected_version, expected_gui_support):
        metadata = parse_firmware_metadata(config)
        assert metadata["os_version"] == expected_version
        assert metadata["with_gui_support"] is expected_gui_support


    @pytest.mark.parametrize(
        "config, expected_error",
        [
            (
                {
                    "software": {
                        "scripts": (
                            {"filename": "sw-update-script.sh", "data": "1.9.3"},
                        )
                    }
                },
                "check_os_version.py is missing",
            ),
            (
                {
                    "software": {
                        "scripts": (
                            {"filename": "check_os_version.py", "data": 1239},
                            {"filename": "sw-update-script.sh", "data": "1.9.3"},
                        )
                    }
                },
                "Invalid GUI support information",
            ),
            (
                {
                    "software": {
                        "scripts": (
                            {"filename": "check_os_version.py", "data": "WITH_GUI_SUPPORT"},
                            {"filename": "sw-update-script.sh", "data": ""},
                        )
                    }
                },
                "Invalid firmware version",
            ),
            (
                {
                    "software": {
                        "scripts": (
                            {"filename": "check_os_version.py", "data": "WITH_GUI_SUPPORT"},
                        )
                    }
                },
                "sw-update-script.sh is missing",
            ),
            (
                {
                    "software": {
                        "scripts": (
                            {"filename": "check_os_version.py", "data": ""},
                            {"filename": "check_os_version.py", "data": "WITH_GUI_SUPPORT"},
                            {"filename": "sw-update-script.sh", "data": "1.9.3"},
                        )
                    }
                },
                "too many check_os_version.py scripts (found 2)",
            ),
            (
                {
                    "software": {
                        "scripts": (
                            {"filename": "check_os_version.py", "data": ""},
                            {"filename": "sw-update-script.sh", "data": "1.9.3"},
                            {"filename": "sw-update-script.sh", "data": "1.9.4"},
                        )
                    }
                },
                "too many sw-update-script.sh scripts (found 2)",
            ),
        ],
    )
    def test_parse_firmware_metadata_incorrect(self, config, expected_error):
        with pytest.raises(InvalidFirmwareError) as excinfo:
            parse_firmware_metadata(config)

        assert expected_error in str(excinfo.value)
