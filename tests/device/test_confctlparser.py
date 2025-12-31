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
import random
import string
from pathlib import Path

import pytest

from device import DEVICE_TESTS_DIR
from mpa.device.common import ConfctlParser

SYSCTL_CONF = DEVICE_TESTS_DIR / 'data/config_sysctl.conf'
SYSCTL_CONF_WITH_COMMENTS = DEVICE_TESTS_DIR / 'data/config_sysctl_with_comments.conf'


def use_temporary_file(func):
    def wrapper(original_path):
        random_filename = ''.join(random.choices(string.ascii_letters + string.digits, k=10)) + '.tmp'
        temp_path = Path('/tmp') / random_filename

        with open(original_path, 'r') as src, open(temp_path, 'w') as dst:
            dst.write(src.read())
        try:
            result = func(temp_path)
        finally:
            pass
        return result
    return wrapper


@pytest.fixture(scope="function")
def config_path(request):
    @use_temporary_file
    def tmp_file(path):
        return path

    return tmp_file(request.param)


@pytest.mark.parametrize('config_path', [SYSCTL_CONF, SYSCTL_CONF_WITH_COMMENTS], indirect=True)
def test_read_config(config_path):
    conf = ConfctlParser(config_path)
    assert conf["kernel.sysrq"] == '0'


@pytest.mark.parametrize('config_path', [SYSCTL_CONF, SYSCTL_CONF_WITH_COMMENTS], indirect=True)
def test_write_config(config_path):
    conf = ConfctlParser(config_path)
    conf["kernel.sysrq"] = '176'
    conf.write()
    with config_path.open('r') as file:
        for line in file:
            if 'kernel.sysrq' in line:
                assert line.strip() in ('kernel.sysrq=176', 'kernel.sysrq = 176')
