#!/usr/bin/env python3
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
import argparse

import json
import select
import sys
import typing
from systemd import journal  # type: ignore

# Local imports
from mpa.communication import client as com_client
from mpa.common.logger import Logger
from mpa.common.killer_thread import KillerThread
from mpa.communication.process import run_command_unchecked
from mpa.config.common import CONFIG_DIR_ROOT

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")

# TODO we shall ensure, that HM_CFG_PATH is not writable by somebody with lower rights than our process, because we execute
# commands from that file (see read_logs last run_command_unchecked)
HM_CFG_PATH = CONFIG_DIR_ROOT / "healthmonitor/health_monitor.cfg"


# TODO why do we run commands unchecked?
def read_logs(events_list: typing.Dict[str, typing.Any]) -> None:
    def entry_is_log(entry: typing.Mapping[str, typing.Any]) -> bool:
        if entry['SYSLOG_IDENTIFIER'] in events_list.keys():
            if events_list[entry['SYSLOG_IDENTIFIER']]['type'] == "logs":
                return True
        return False

    logger.info("Started listening thread")
    logger.info(f"Events: {events_list}")
    journal_reader = journal.Reader()
    journal_reader.log_level(journal.LOG_INFO)
    journal_reader.this_boot()
    journal_reader.this_machine()
    journal_reader.seek_tail()
    journal_reader.get_previous()
    polling_object = select.poll()
    journal_fd = journal_reader.fileno()
    poll_event_mask = journal_reader.get_events()
    polling_object.register(journal_fd, poll_event_mask)
    while True:
        try:
            if polling_object.poll(10000) and journal_reader.process() == journal.APPEND:
                for entry in journal_reader:
                    if entry_is_log(entry):
                        trigger_value = events_list[entry['SYSLOG_IDENTIFIER']]['trigger_value']
                        if trigger_value['type'] == "contains":
                            for value in trigger_value['value'].split("|"):
                                if value in entry['MESSAGE']:
                                    logger.error(f"{entry['SYSLOG_IDENTIFIER']} encountered critical error")
                                    if events_list[entry['SYSLOG_IDENTIFIER']]['action']['type'] == "systemctl":
                                        if events_list[entry['SYSLOG_IDENTIFIER']]['action']['action'] == "restart":
                                            run_command_unchecked(f"systemctl restart {entry['SYSLOG_IDENTIFIER']}")
                                    elif events_list[entry['SYSLOG_IDENTIFIER']]['action']['type'] == "custom_command":
                                        run_command_unchecked(f"{events_list[entry['SYSLOG_IDENTIFIER']]['action']['action']}")
                                    break
        except Exception as e:
            logger.error("read_logs failed with exception")
            logger.exception(e)


def main() -> None:
    _parser = argparse.ArgumentParser(prog='Device health monitor')
    com_client.add_command_line_params(_parser)
    _args = _parser.parse_args()
    _client = com_client.Client(args=_args)
    messages: typing.Dict[str, typing.Any] = {}

    _client.register_responders(messages)

    logger.info("Started health monitor")
    events_list = json.loads(HM_CFG_PATH.read_text())
    thread = KillerThread(target=read_logs, args=(events_list,))
    thread.start()
    while True:
        _client.wait_and_receive()


if __name__ == "__main__":
    main()
