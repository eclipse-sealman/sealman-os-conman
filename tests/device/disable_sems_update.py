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
import json
from mock import patch
from mpa.device.smartems import update_config_set, update_config_get

SET_CONFIG_FILE = "tmp_config_file"
GET_CONFIG_FILE = "device_config/tests/data/default_update_config"

DEFAULT_UPDATE_VALUE = {
    "username": "eg",
    "password": "500",
    "url": "http://smart.ems"
}


def teardown_module(module):
    import os
    if os.path.exists(SET_CONFIG_FILE):
        os.remove(SET_CONFIG_FILE)


@patch('device_config.device_daemon.smartems_config_file', SET_CONFIG_FILE)
@pytest.mark.parametrize("payload",
                         [
                             pytest.param({"update": {"username": ""}}, marks=pytest.mark.xfail),
                             pytest.param({"update": {"username": "", "password": ""}}, marks=pytest.mark.xfail),
                             pytest.param({"update": {"username": "", "url": ""}}, marks=pytest.mark.xfail),
                             pytest.param({"update": {"password": ""}}, marks=pytest.mark.xfail),
                             pytest.param({"update": {"password": "", "url": ""}}, marks=pytest.mark.xfail),
                             pytest.param({"update": {"url": ""}}, marks=pytest.mark.xfail),
                             pytest.param({"update": {"username": "test", "password": "test", "url": "https://localhost"}})
                         ]
                         )
def test_set_config_missing_parameters(payload):
    assert update_config_set(json.dumps(payload)) == "OK Smart EMS config successfuly updated"


@patch('device_config.device_daemon.smartems_config_file', GET_CONFIG_FILE)
def test_get_config_missing_parameters():
    assert update_config_get("") == DEFAULT_UPDATE_VALUE
