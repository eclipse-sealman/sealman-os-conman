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
import json
from pathlib import Path
from unittest.mock import patch

import pytest

import mpa.device.azure
from device import DEVICE_TESTS_DIR
from mpa.communication.inter_process_lock import InterProcessLock

TEST_TMP_PATH = Path("/tmp/azure_test")
SET_CONFIG_FILE = Path(f"{TEST_TMP_PATH}/tmp_config_file")
SET_CONFIG_FILE_VALIDATED = Path(f"{TEST_TMP_PATH}/tmp_config_file.validated")
DEFAULT_CONFIG_FILE = DEVICE_TESTS_DIR / "data/default_iotedge_config"
SET_FULL_CONFIG_FILE_INPUT = DEVICE_TESTS_DIR / "data/iotedge_config_set_config_input"
SET_FULL_CONFIG_FILE_RESULT = DEVICE_TESTS_DIR / "data/iotedge_config_set_config_result"

AZURE_LOCK = InterProcessLock(Path(f"{TEST_TMP_PATH}/lock.azure"), stale_lock_seconds=600)


def setup_module(module):
    from shutil import copyfile
    TEST_TMP_PATH.mkdir()
    copyfile(DEFAULT_CONFIG_FILE, SET_CONFIG_FILE)


def teardown_module(module):
    from shutil import rmtree
    rmtree(TEST_TMP_PATH)


@pytest.fixture(autouse=True)
def run_before_and_after_tests(tmpdir):
    from shutil import copyfile
    copyfile(DEFAULT_CONFIG_FILE, SET_CONFIG_FILE)
    yield
    pass


@patch('mpa.device.azure.Azure.AZURE_LOCK', AZURE_LOCK)
@pytest.mark.parametrize("payload",
                         [
                             pytest.param({"registration_id": "regID", "scope_id": "idScope"})
                         ]
                         )
@patch('mpa.communication.process.run_command_unchecked')
def test_set_tpm_parameters(mock_RunCommand, payload):
    mock_RunCommand.side_efect = lambda _: 0
    azure = mpa.device.azure.Azure(cert_dir=TEST_TMP_PATH)
    azure.AZURE_CONFIG_FILE = SET_CONFIG_FILE
    azure.set_tpm(json.dumps(payload).encode())
    azure_config = azure._load_azure_config()

    assert azure_config['provisioning']['source'] == "dps"
    assert azure_config['provisioning']['attestation']['method'] == "tpm"
    assert "registration_id" in azure_config['provisioning']['attestation']
    assert azure_config['provisioning']['attestation']['registration_id'] == payload['registration_id']
    assert "id_scope" in azure_config['provisioning']
    assert azure_config['provisioning']['id_scope'] == payload['scope_id']


@patch('mpa.device.azure.Azure.AZURE_LOCK', AZURE_LOCK)
@patch('mpa.communication.process.run_command_unchecked')
def test_set_connection_string(mock_RunCommand):
    azure = mpa.device.azure.Azure(cert_dir=TEST_TMP_PATH)
    azure.AZURE_CONFIG_FILE = SET_CONFIG_FILE
    azure.set_connection_string((json.dumps("test_connection_string").encode()))
    azure_config = azure._load_azure_config()

    assert azure_config['provisioning']['source'] == "manual"
    assert azure_config['provisioning']['connection_string'] == "test_connection_string"


# {"ca": "ca_content", "device_ca": "dev_ca_content", "private": "priv_content"}
# azure_set_cert
# IOTEDGE_ICUSTOM_CERT_DIR = Path('/etc/eg/certs/iotedge')
# @patch('mpa.device.azure.Azure.AZURE_LOCK', AZURE_LOCK)
# @patch('mpa.communication.process.run_command_unchecked')
# def test_set_custom_cert(mock_RunCommand):
#     azure = mpa.device.azure.Azure(cert_dir=TEST_TMP_PATH)
#     azure.AZURE_CONFIG_FILE = SET_CONFIG_FILE
#     config = {"trusted_ca_certs": "ca_content", "device_ca_cert": "dev_ca_content", "device_ca_pk": "priv_content"}
#     azure.set_cert(json.dumps(config).encode())
#     azure_config = azure._load_azure_config()

#     assert azure_config['certificates']['device_ca_cert'] == f'file://{TEST_TMP_PATH}/device-ca.pem'
#     assert azure_config['certificates']['device_ca_pk'] == f'file://{TEST_TMP_PATH}/private.pem'
#     assert azure_config['certificates']['trusted_ca_certs'] == f'file://{TEST_TMP_PATH}/ca-full-chain.pem'


@patch('mpa.device.azure.Azure.AZURE_LOCK', AZURE_LOCK)
def test_get_full_config():
    import toml
    azure = mpa.device.azure.Azure(cert_dir=TEST_TMP_PATH)
    azure.AZURE_CONFIG_FILE = SET_CONFIG_FILE
    returned_config = azure.get_configfile("".encode())["azure_configfile"]
    default_config_file = toml.load(DEFAULT_CONFIG_FILE)

    assert type(returned_config) is type(default_config_file)
    assert returned_config == default_config_file


@patch('mpa.device.azure.Azure.AZURE_LOCK', AZURE_LOCK)
def test_set_full_config():
    import toml
    with open(SET_FULL_CONFIG_FILE_INPUT, "r") as fd:
        new_config = fd.read()
    azure = mpa.device.azure.Azure(cert_dir=TEST_TMP_PATH)
    azure.AZURE_CONFIG_FILE = SET_CONFIG_FILE
    azure.AZURE_CONFIG_FILE_VALIDATED = SET_CONFIG_FILE
    iotedge = Path('/bin/iotedge')
    assert not iotedge.exists()
    iotedge.symlink_to('/bin/true')
    azure.set_configfile(json.dumps({"azure_configfile": new_config}).encode())
    iotedge.unlink()
    azure_config = azure._load_azure_config()
    full_config_expected = toml.load(SET_FULL_CONFIG_FILE_RESULT)
    full_config_on_device = azure.get_configfile("".encode())["azure_configfile"]

    assert 'hostname' not in azure_config
    assert azure_config['provisioning']['connection_string'] == "test_connection_string"
    assert azure_config['auto_reprovisioning_mode'] == "Dynamic"
    assert type(full_config_expected) is type(full_config_on_device)
    assert full_config_expected == full_config_on_device


@patch('mpa.device.azure.Azure.AZURE_LOCK', AZURE_LOCK)
@patch('mpa.communication.process.run_command_unchecked')
def test_set_hostname(mock_RunCommand):
    azure = mpa.device.azure.Azure(cert_dir=TEST_TMP_PATH)
    azure.AZURE_CONFIG_FILE = SET_CONFIG_FILE
    azure.set_hostname(json.dumps({"hostname": "test_hostname"}).encode())
    azure_config = azure._load_azure_config()
    assert azure_config['hostname'] == "test_hostname"


# @patch('mpa.device.azure.Azure.AZURE_LOCK', AZURE_LOCK)
# @patch('mpa.communication.process.run_command_unchecked')
# def test_remove_custom_cert(mock_RunCommand):
#     azure = mpa.device.azure.Azure(cert_dir=TEST_TMP_PATH)
#     azure.AZURE_CONFIG_FILE = SET_CONFIG_FILE
#     config = {"trusted_ca_certs": "ca_content", "device_ca_cert": "dev_ca_content", "device_ca_pk": "priv_content"}
#     azure.set_cert(json.dumps(config).encode())
#     azure.remove_cert("".encode())
#     azure_config = azure._load_azure_config()
#     assert 'certificates' not in azure_config
