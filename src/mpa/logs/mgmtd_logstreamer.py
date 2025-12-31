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
import select
import sys

from io import BytesIO
from itertools import chain
from pathlib import Path
from systemd import journal  # type: ignore
from typing import Optional
from zipfile import ZipFile, ZIP_DEFLATED

# Local imports
import mpa.communication.topics as topics
from mpa.communication import client as com_client
from mpa.communication.client import convert_exception_to_message_failure_status
from mpa.communication.client import guarded
from mpa.communication.client import sync
from mpa.common.logger import Logger
from mpa.common.killer_thread import KillerThread
from mpa.device.common import get_serial_number

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")

_parser = argparse.ArgumentParser(prog='Log streamer daemon')
com_client.add_command_line_params(_parser)
_args = _parser.parse_args()
_client = com_client.Client(args=_args)


stream_listener_exists = False
streamer_thread: Optional[KillerThread] = None


def download_logs(message: bytes) -> bytes:
    def add_string_as_file(zip_file: ZipFile, data: str, file_name: Path) -> None:
        zip_file.writestr(file_name.name, data)

    def add_file(zip_file: ZipFile, path: Path) -> None:
        try:
            zip_file.write(path, path.name)
        except Exception as exc:
            logger.exception(exc)
            add_string_as_file(zip_file,
                               convert_exception_to_message_failure_status(exc),
                               path)

    log_directory = Path('/var/log/')
    version_files = (Path('/etc/os-release'),
                     Path('/etc/sw-version'),
                     Path('/etc/hw-version'))
    zip_buffer = BytesIO()
    with ZipFile(zip_buffer, "a", ZIP_DEFLATED, False) as zip_file:
        add_string_as_file(zip_file, get_serial_number(), Path('eg-serial-number'))
        for file in chain(log_directory.glob('*.log*'), version_files):
            add_file(zip_file, file)

    return zip_buffer.getvalue()


def stream_logs() -> None:
    global stream_listener_exists
    global _client
    j = journal.Reader()
    j.log_level(journal.LOG_INFO)
    j.this_boot()
    j.this_machine()
    j.seek_tail()
    j.get_previous()
    p = select.poll()
    journal_fd = j.fileno()
    poll_event_mask = j.get_events()
    p.register(journal_fd, poll_event_mask)
    while stream_listener_exists:
        if p.poll(5000):
            if j.process() == journal.APPEND:
                for entry in j:
                    _client.send("log.stream", f"{entry}")


def topic_watcher(state: bool) -> None:
    logger.info(f"State of topic_watcher: {state}")
    global stream_listener_exists
    global streamer_thread
    if state != stream_listener_exists:
        stream_listener_exists = state
        if stream_listener_exists:
            streamer_thread = KillerThread(target=stream_logs)
            streamer_thread.start()
        elif streamer_thread is not None:
            streamer_thread.join()
            streamer_thread = None
            logger.debug("Thread stopped")
        else:
            logger.error("Inconsistent state in mgmtd-logstreamer, we expected streamer thread to be down, but it existed...")
    else:
        logger.info("No change in log streamer state")
    return


def main() -> None:
    messages = {}
    messages[topics.logstreamer.download_logs] = guarded(sync(download_logs))

    _client.register_responders(messages)
    _client.register_topic_watcher("log.stream", topic_watcher, only_responders=False)

    while True:
        _client.wait_and_receive()


if __name__ == "__main__":
    main()
