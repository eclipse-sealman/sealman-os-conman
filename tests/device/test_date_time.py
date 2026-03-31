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
import pytest
from unittest.mock import patch, call

from mpa.device.date_time import set_time, write_time
from mpa.communication.common import InvalidParameterError, InvalidPreconditionError


NTP_ENABLED = {"date_time": {"ntp_enabled": True}}
NTP_DISABLED = {"date_time": {"ntp_enabled": False}}


@patch('mpa.device.date_time.read_config')
def test_set_time_fails_when_ntp_enabled(mock_read_config):
    mock_read_config.return_value = NTP_ENABLED
    with pytest.raises(InvalidPreconditionError):
        write_time({"datetime": "2026-01-01 12:00:00"})


@patch('mpa.device.date_time.run_command')
@patch('mpa.device.date_time.read_config')
def test_set_time_four_digit_year(mock_read_config, mock_run_command):
    mock_read_config.return_value = NTP_DISABLED
    write_time({"datetime": "2026-03-31 14:30:00"})
    mock_run_command.assert_called_once_with('pkexec timedatectl set-time "2026-03-31 14:30:00"')


@patch('mpa.device.date_time.run_command')
@patch('mpa.device.date_time.read_config')
def test_set_time_two_digit_year(mock_read_config, mock_run_command):
    mock_read_config.return_value = NTP_DISABLED
    write_time({"datetime": "26-03-31 14:30:00"})
    mock_run_command.assert_called_once_with('pkexec timedatectl set-time "2026-03-31 14:30:00"')


@patch('mpa.device.date_time.read_config')
def test_set_time_invalid_format(mock_read_config):
    mock_read_config.return_value = NTP_DISABLED
    with pytest.raises(InvalidParameterError):
        write_time({"datetime": "not-a-date"})


@patch('mpa.device.date_time.read_config')
def test_set_time_invalid_month(mock_read_config):
    mock_read_config.return_value = NTP_DISABLED
    with pytest.raises(InvalidParameterError):
        write_time({"datetime": "2026-13-01 10:00:00"})


@patch('mpa.device.date_time.read_config')
def test_set_time_invalid_hour(mock_read_config):
    mock_read_config.return_value = NTP_DISABLED
    with pytest.raises(InvalidParameterError):
        write_time({"datetime": "2026-01-01 25:00:00"})


@patch('mpa.device.date_time.run_command')
@patch('mpa.device.date_time.read_config')
def test_set_time_message_handler(mock_read_config, mock_run_command):
    mock_read_config.return_value = NTP_DISABLED
    message = json.dumps({"datetime": "2026-03-31 09:00:00"}).encode()
    set_time(message)
    mock_run_command.assert_called_once_with('pkexec timedatectl set-time "2026-03-31 09:00:00"')

