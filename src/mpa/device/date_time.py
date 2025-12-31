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
import json

from configparser import ConfigParser
from typing import Any, Dict

# Local imports
from mpa.common.common import RESPONSE_OK
from mpa.communication.common import expect_empty_message
from mpa.communication.common import get_timezones
from mpa.communication.common import InvalidParameterError
from mpa.communication.message_parser import get_bool, get_dict, get_int, get_str, get_optional_str, get_str_with_default
from mpa.communication.process import run_command
from mpa.config.configfiles import ConfigFiles

config_files = ConfigFiles()
# TODO is timesyncd_config_file optional?
timesyncd_config_file = config_files.add("timesyncd", "systemd/timesyncd.conf", is_expected=False)
config_files.verify()

NTP_CONFIG_TEMPLATE = """
[Time]
{NTP_LINE_PREFIX}NTP={NTP}
FallbackNTP={FALLBACK_NTP}
RootDistanceMaxSec={ROOT_DISTANCE}
PollIntervalMinSec={INTERVAL_MIN}
PollIntervalMaxSec={INTERVAL_MAX}
"""

DEFAULT_NTP_SERVER = ""
DEFAULT_NTP_FALLBACK_SERVERS = "0.de.pool.ntp.org 1.de.pool.ntp.org 2.de.pool.ntp.org 3.de.pool.ntp.org"
DEFAULT_ROOT_DISTANCE_MAX_SEC = 5
DEFAULT_POLL_INTERVAL_MIN_SEC = 32
DEFAULT_POLL_INTERVAL_MAX_SEC = 2048


def timedatectl_output() -> str:
    return run_command('timedatectl show').stdout.decode('UTF-8')


def show_time(message: bytes) -> str:
    expect_empty_message(message, "show_time()")
    return f"{RESPONSE_OK} {timedatectl_output()}"


def read_config() -> Dict[str, Dict[str, Any]]:
    conpar = ConfigParser()
    conpar.read(timesyncd_config_file)
    conpar.read_string(f"[Status]\n{timedatectl_output()}")
    if 'Time' not in conpar:
        conpar.add_section('Time')
    time_sec = conpar['Time']
    retval: Dict[str, Any] = {}
    retval['ntp_server'] = time_sec.get('NTP', DEFAULT_NTP_SERVER)
    retval['fallback_servers'] = time_sec.get('FallbackNTP', DEFAULT_NTP_FALLBACK_SERVERS)
    retval['interval_minimum'] = time_sec.getint('PollIntervalMinSec', DEFAULT_POLL_INTERVAL_MIN_SEC)
    retval['interval_maximum'] = time_sec.getint('PollIntervalMaxSec', DEFAULT_POLL_INTERVAL_MAX_SEC)
    status_sec = conpar['Status']
    retval['ntp_enabled'] = status_sec.getboolean('NTP')
    retval['timezone'] = status_sec['timezone']
    return {"date_time": retval}


def get_config(message: bytes) -> Dict[str, Dict[str, Any]]:
    expect_empty_message(message, "datetime.get_config()")
    return read_config()


def write_ntp_config(user_data: Dict[str, str]) -> None:
    ntp_server = get_optional_str(user_data, 'ntp_server')
    if len(ntp_server) == 0:
        ntp_line_prefix = '#'
    else:
        ntp_line_prefix = ''
    ntp_server_fallback = get_str_with_default(user_data, 'fallback_servers', default=DEFAULT_NTP_FALLBACK_SERVERS)
    interval_minimum = get_int(user_data, 'interval_minimum')
    interval_maximum = get_int(user_data, 'interval_maximum')

    if interval_minimum < 16:
        raise InvalidParameterError("interval_minimum must be greater than 16")

    if interval_minimum > 2048:
        raise InvalidParameterError("interval_minimum must be lesser than 2048")

    if interval_maximum < 16:
        raise InvalidParameterError("interval_maximum must be greater than 16")

    if interval_maximum > 2048:
        raise InvalidParameterError("interval_maximum must be lesser than 2048")

    if interval_maximum < interval_minimum:
        raise InvalidParameterError("interval_maximum can not be lesser than interval_minimum")

    timesyncdconf = NTP_CONFIG_TEMPLATE.format(NTP_LINE_PREFIX=ntp_line_prefix,
                                               NTP=ntp_server, FALLBACK_NTP=ntp_server_fallback,
                                               INTERVAL_MIN=interval_minimum, INTERVAL_MAX=interval_maximum,
                                               ROOT_DISTANCE=DEFAULT_ROOT_DISTANCE_MAX_SEC)
    # TODO use daemons with proper permissions to avoid those chmods
    # Change chmod to ntp config to allow this daemon to write configuration
    run_command(f"pkexec /bin/chmod 777 {timesyncd_config_file}")
    with open(timesyncd_config_file, "w") as file:
        file.write(timesyncdconf)
    # Restore the original permissions
    run_command(f"pkexec /bin/chmod 644 {timesyncd_config_file}")


def write_timezone_config(config: Dict[str, str]) -> None:
    timezone = get_str(config, 'timezone')
    systemd_timezones = get_timezones()
    # Looks like "Universal" is special timezone used by default by systemd
    # which is settable but not listed as available...
    if timezone not in systemd_timezones and timezone != "Universal":
        raise InvalidParameterError(f"Unknown timezone {timezone}")
    run_command(f"pkexec timedatectl set-timezone {timezone}")


def toggle_ntp(user_data: Dict[str, str]) -> None:
    action = get_bool(user_data, "ntp_enabled")
    if action:
        run_command("pkexec timedatectl set-ntp true")
    else:
        run_command("pkexec timedatectl set-ntp false")


def set_config(message: bytes) -> None:
    config = get_dict(json.loads(message), 'date_time')
    write_ntp_config(config)
    write_timezone_config(config)
    toggle_ntp(config)


def set_ntp_server(message: bytes) -> None:
    user_data = json.loads(message)
    write_ntp_config(user_data)


def set_timezone(message: bytes) -> None:
    config = json.loads(message)
    write_timezone_config(config)


def manage_ntp_service(message: bytes) -> None:
    user_data = json.loads(message)
    toggle_ntp(user_data)
