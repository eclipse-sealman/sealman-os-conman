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
from pathlib import Path
from time import sleep
from typing import Any, Callable, Dict, Optional

# Local imports
import mpa.communication.topics as topics
from mpa.common.common import RESPONSE_OK
from mpa.common.logger import Logger
from mpa.communication import client as com_client
from mpa.communication.client import background, guarded
from mpa.communication.common import SWUpdateError
from mpa.communication.message_parser import get_bool, get_file
from mpa.swupdate.swupdate_client import SWUpdateClient
from mpa.swupdate.swupdate_types import RecoveryStatus, SwupdateDaemonMessages

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")


def swupdate_progress_callback(swupdate_progess: dict[str, Any]) -> None:
    __send_response_over_rt(swupdate_progess)


def __send_response_over_rt(message: dict[str, Any]) -> None:
    _client.send(f"{topics.dev.swupdate}.rt", message)


def perform_update(message: bytes) -> Optional[str]:
    update_file_path = get_file(json.loads(message), "filepath")
    dry_run = get_bool(json.loads(message), "dryrun")
    reboot = get_bool(json.loads(message), "reboot")
    logger.debug(f"SWUpdate reqest: {update_file_path=} {dry_run=} {reboot=}")
    c = SWUpdateClient()

    if dry_run:
        __send_response_over_rt({"type": "daemon_status", "data":
                                {"message": "Running image check",
                                 "status": SwupdateDaemonMessages.INFO},
                                "dry_run": dry_run})
        check_status = c.perform_update(Path(update_file_path), dry_run, swupdate_progress_callback)
        if check_status and check_status == RecoveryStatus.SUCCESS:
            __send_response_over_rt({"type": "daemon_status", "data":
                                    {"message": "Image check pass, running software update",
                                     "status": SwupdateDaemonMessages.INFO},
                                    "dry_run": dry_run})
        else:
            __send_response_over_rt({"type": "daemon_status", "data":
                                    {"message": "Image check failed",
                                     "status": SwupdateDaemonMessages.ERROR},
                                    "dry_run": dry_run})
            raise SWUpdateError("Image check fail")

    # Perform full update
    sleep(5)
    update_status = c.perform_update(Path(update_file_path), False, swupdate_progress_callback)
    logger.info(f"Update status: mgmtd-swupdate {str(update_status)}")
    if update_status and update_status == RecoveryStatus.SUCCESS and reboot:
        __send_response_over_rt({"type": "daemon_status", "data":
                                {"message": "Update complete, system will reboot in about 10 seconds",
                                 "status": SwupdateDaemonMessages.SUCCESS},
                                 "dry_run": False})
        sleep(5)
        _client.query(topics.dev.reboot, "")
    elif update_status == RecoveryStatus.SUCCESS:
        __send_response_over_rt({"type": "daemon_status", "data":
                                {"message": "Update complete!",
                                 "status": SwupdateDaemonMessages.SUCCESS},
                                 "dry_run": False})
    elif update_status != RecoveryStatus.SUCCESS:
        __send_response_over_rt({"type": "daemon_status", "data":
                                {"message": "Software update failed!",
                                 "status": SwupdateDaemonMessages.ERROR},
                                 "dry_run": False})
        raise SWUpdateError("Image install fail")
    return RESPONSE_OK


_parser = argparse.ArgumentParser(prog='SWUpdate daemon')
com_client.add_command_line_params(_parser)
_args = _parser.parse_args()
_client = com_client.Client(args=_args)
messages: Dict[str, Any] = {}


def main() -> None:
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
