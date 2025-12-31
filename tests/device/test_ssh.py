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
from unittest.mock import patch
from pathlib import Path

from mpa.device.common import AuthorizedKeys, get_user_primary_group
from mpa.communication.common import InvalidPreconditionError, InvalidParameterError

TEST_TMP_PATH = Path("/tmp/ssh_test")
ADMIN_TMP_PATH = Path("/tmp/ssh_test/admin")
USER_TMP_PATH = Path("/tmp/ssh_test/user")

VALID_SSH_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDDfE0YwLU+gLNA/v56M+VsuaOW4Xr7bOz\
Nmw0oC/i6MjAO23zjlmexGA3rv/cwdpc7G0U6E4cJWiF+7OzWYQ14onkUO7dqdQRD2ntbrQ2jcqMP7r0bcItK9uw\
5PIPNEkeLK1r0BVQ7pz73YIUCuv7OeaqauI3Jb8HCp+yHDS363cbW+d2FOeRv+cbfHPSvQu57xhU5xGc+gXE/Our\
Gq74r72cx3QrXqzBgWemoU+NoFyA+ubMhxm8GTlo3lWw06deCY1rASS6nUwfnATaiFVM0dljt19rVesUDS/ycA2H\
omvt3W6Ho6gSerqcPpusuFvrokZFPkYeTIgvmj1SRIZq3X+UtUYPZKL5+XC5l03X+v98p0MHAT/SFB9IWxK18jSv\
RkCXXD94sZaGorbZzmQPzXPra0bwqbhm1u3DmzwuNIrtf6ppYVqUYtCvOiI10FjwusUoFFrY2RHErtxUCKPqY1jE\
vnP+tEpJssRrHOHc+LVJuikm48djKKUPuvZOZY6s= root@eg\n"

INVALID_SSH_KEY = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris massa justo, malesuada et nulla eu,\
sollicitudin tempor est. Ut nec urna non augue sagittis posuere non et arcu. Mauris luctus mattis elit, ultricies varius\
nibh. Morbi lobortis sagittis pretium. Sed imperdiet justo in orci scelerisque, sed bibendum sapien convallis. Sed interdum\
interdum nulla, ac vehicula neque accumsan in. In vel nibh quam. Mauris semper a arcu vitae blandit. Nulla eros dolor,\
pulvinar eu nunc cursus, blandit congue augue. Praesent ligula nunc, bibendum sed finibus eget, imperdiet a elit."


@pytest.fixture(autouse=True)
def run_before_and_after_tests(tmpdir):
    TEST_TMP_PATH.mkdir()
    ADMIN_TMP_PATH.mkdir()
    USER_TMP_PATH.mkdir()
    yield
    from shutil import rmtree
    rmtree(TEST_TMP_PATH)


def test_get_primary_group():
    # We use users and groups of system on which tests run!!!
    # We run tests in docker and appropriate users/groups are created
    # in dockerfile (at the time of creation of this comment builder/Dockerfile)
    # if this test fails check if your container is up to date
    assert get_user_primary_group("admin") == 'devadmin'


@patch('mpa.device.common.AuthorizedKeys._get_user_ssh_directory')
def test_add_ssh_key(mocked_function):
    mocked_function.return_value = ADMIN_TMP_PATH
    AuthorizedKeys("admin").add_ssh_key(VALID_SSH_KEY)
    with open(f"{ADMIN_TMP_PATH}/.ssh/authorized_keys", "r") as fd:
        data = fd.read()
    assert data == VALID_SSH_KEY


@patch('mpa.device.common.AuthorizedKeys._get_user_ssh_directory')
def test_add_ssh_key_for_root(mocked_function):
    try:
        AuthorizedKeys("root").add_ssh_key(VALID_SSH_KEY)
    except InvalidPreconditionError as ex:
        assert str(ex) == "Change of SSH keys for root is forbidden"


@patch('mpa.device.common.AuthorizedKeys._get_user_ssh_directory')
def test_add_invalid_ssh_key(mocked_function):
    mocked_function.return_value = ADMIN_TMP_PATH
    try:
        AuthorizedKeys("admin").add_ssh_key(INVALID_SSH_KEY)
    except InvalidParameterError as ex:
        assert str(ex).startswith("Received invalid ssh public key")


@patch('mpa.device.common.AuthorizedKeys._get_user_ssh_directory')
def test_remove_ssh_key(mocked_function):
    mocked_function.return_value = ADMIN_TMP_PATH
    AuthorizedKeys("admin").add_ssh_key(VALID_SSH_KEY)
    AuthorizedKeys("admin").delete_ssh_key(0)
    with open(f"{ADMIN_TMP_PATH}/.ssh/authorized_keys", "r") as fd:
        data = fd.read()
    assert data == ""


@patch('mpa.device.common.AuthorizedKeys._get_user_ssh_directory')
def test_add_two_same_keys_ssh_key(mocked_function):
    mocked_function.return_value = ADMIN_TMP_PATH
    AuthorizedKeys("admin").add_ssh_key(VALID_SSH_KEY)
    try:
        AuthorizedKeys("admin").add_ssh_key(VALID_SSH_KEY)
    except InvalidPreconditionError as ex:
        assert str(ex) == "Key already present in authorized_keys"
