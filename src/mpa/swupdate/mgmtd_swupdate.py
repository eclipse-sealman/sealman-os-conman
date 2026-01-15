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
import sys
import time
from enum import IntEnum
from pathlib import Path
from typing import Any, Callable, Dict, Optional

# Local imports
import mpa.communication.topics as topics
import mpa.swupdate.swupdate as swupdate
from mpa.common.common import RESPONSE_OK
from mpa.common.logger import Logger
from mpa.communication import client as com_client
from mpa.communication.client import background, guarded
from mpa.communication.message_parser import get_file
from mpa.communication.common import SWUpdateError
from mpa.device.common import reboot_device

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")
_client: Optional[com_client.Client] = None


class SwupdateDaemonMessage(IntEnum):
    INFO = 0
    SUCCESS = 1
    ERROR = 2


def __send_response_over_rt(data: dict[str, Any]) -> None:
    assert _client is not None
    _client.send(f"{topics.dev.swupdate}.rt", data)


def full_update_with_reboot(
    swupdate_file: Path,
    *,
    progress_callback: Optional[swupdate.ProgressCallback] = None,
    description_filter: swupdate.DescriptionFilter = swupdate.default_descritpion_filter,
    logging_func: Callable[[dict[str, Any]], None] = lambda _: None,
) -> None:
    """Perform a dry run, then update and finally reboot.

    This function additionally sends real time messages to CLI and webui.
    """
    logging_func({
        "type": "daemon_status",
        "dry_run": True,
        "data": {"message": "Running image check", "status": SwupdateDaemonMessage.INFO},
    })
    success, desc = swupdate.update(
        dry_run=True,
        swupdate_file=swupdate_file,
        progress_callback=progress_callback,
        description_filter=description_filter
    )
    if success:
        logging_func({
            "type": "daemon_status",
            "dry_run": True,
            "data": {"message": "Image check pass, running software update", "status": SwupdateDaemonMessage.INFO},
        })
    else:
        logging_func({
            "type": "daemon_status",
            "dry_run": True,
            "data": {"message": "Image check failed", "status": SwupdateDaemonMessage.ERROR},
        })
        raise SWUpdateError(desc)

    # SWUpdate needs some time to finish processing an update
    # it responds with NACK if new REQ_INSTALL comes too soon
    time.sleep(5)

    success, desc = swupdate.update(
        dry_run=False,
        swupdate_file=swupdate_file,
        progress_callback=progress_callback,
        description_filter=description_filter
    )
    if success:
        logging_func({
            "type": "daemon_status",
            "dry_run": False,
            "data": {
                "message": "Update complete, system will reboot in about 10 seconds",
                "status": SwupdateDaemonMessage.SUCCESS
            },
        })
    else:
        logging_func({
            "type": "daemon_status",
            "dry_run": False,
            "data": {"message": "Software update failed!", "status": SwupdateDaemonMessage.ERROR},
        })
        raise SWUpdateError(desc)

    reboot_device(b"")


def perform_update(message: bytes) -> Optional[str]:
    def progress_callback(nsteps: int, cur_percent: int, cur_step: int, dry_run: bool) -> None:
        __send_response_over_rt(
            {
                "type": "progress",
                "dry_run": dry_run,
                "data": {"nsteps": nsteps, "cur_percent": cur_percent, "cur_step": cur_step},
            }
        )

    update_file_path = get_file(json.loads(message), "filepath")
    swupdate_file = Path(update_file_path)
    full_update_with_reboot(
        swupdate_file,
        progress_callback=progress_callback,
        logging_func=__send_response_over_rt
    )
    return RESPONSE_OK


def main() -> None:
    global _client
    _parser = argparse.ArgumentParser(prog='SWUpdate daemon')
    com_client.add_command_line_params(_parser)
    _args = _parser.parse_args()
    _client = com_client.Client(args=_args)
    messages: Dict[str, Any] = {}

    def in_bg(topic: str, fun: com_client.SyncHandlerCallable, post_respond: Optional[Callable[[Any], None]] = None) -> None:
        messages[topic] = background(fun, com_client.respond_to(_client, topic), post_respond=post_respond)
    in_bg(topics.dev.swupdate, guarded(perform_update))
    _client.register_responders(messages)

    while True:
        try:
            _client.wait_and_receive()
        except _client.LostRequestList as lre:
            logger.warning(f"Received LostRequestList: {lre}")
        except _client.ConnectionResetError as cre:
            logger.warning(f"Received ConnectionResetError: {cre}")


if __name__ == "__main__":
    main()
