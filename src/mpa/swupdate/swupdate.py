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
import select
import socket
from pathlib import Path
from typing import Callable, Optional

import mpa.swupdate.swupdate_types as t
from mpa.communication.common import SWUpdateError

CHUNK_SIZE = 4096 * 32
IPC_MAGIC = 0x14052001
SOCKET_IPC_PATH = Path("/tmp/sockinstctrl")
SOCKET_PROGRESS_PATH = Path("/tmp/swupdateprog")

#                       description
StatusCallback = Callable[[str], None]
#                          nsteps, cur_percent, cur_step, dry_run
ProgressCallback = Callable[[int, int, int, bool], None]
DescriptionFilter = Callable[[str], bool]


def create_req_install_message(dry_run: bool) -> t.IpcMessage:
    msg = t.IpcMessage()
    msg.magic = IPC_MAGIC
    # TODO
    # decide if we want to dig deeper in case of IntEnum - ctypes.c_int compatibility
    msg.type = t.MsgType.REQ_INSTALL
    req = msg.data.instmsg.req
    req.apiversion = 1
    req.dry_run = t.RunType.DRY_RUN if dry_run else t.RunType.INSTALL
    return msg


def create_get_status_message() -> t.IpcMessage:
    msg = t.IpcMessage()
    msg.magic = IPC_MAGIC
    msg.type = t.MsgType.GET_STATUS
    return msg


def get_status() -> t.IpcMessage:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(str(SOCKET_IPC_PATH))
        s.sendall(create_get_status_message())
        msg = t.IpcMessage()
        s.recv_into(msg)
        return msg


def default_descritpion_filter(desc: str) -> bool:
    return any(x in desc for x in ("parse_hw_compatibility", "check_hw_compatibility", "ERROR"))


def update(
    dry_run: bool,
    swupdate_file: Path,
    *,
    status_callback: Optional[StatusCallback] = None,
    progress_callback: Optional[ProgressCallback] = None,
    description_filter: DescriptionFilter = default_descritpion_filter,
) -> tuple[bool, str]:
    """Perform an update. Return a tuple of success (bool) and description (string) with error information."""

    # SWUpdate expects REQ_INSTALL message and the image to come on the same connection
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as ctrl:
        ctrl.connect(str(SOCKET_IPC_PATH))
        ctrl.sendall(create_req_install_message(dry_run))
        msg = t.IpcMessage()
        ctrl.recv_into(msg)
        if t.MsgType(msg.type) != t.MsgType.ACK:
            raise SWUpdateError("SWUpdate rejects install request - update in progress")

        with swupdate_file.open("rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                try:
                    ctrl.sendall(chunk)
                except BrokenPipeError:
                    # SWUpdate aborted transfer - there is something wrong with the image
                    # details are provided by the control socket, so the function continues
                    break

    # for progress one non blocking connection can be used
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as prog:
        prog.connect(str(SOCKET_PROGRESS_PATH))
        prog.setblocking(False)

        success = False
        description = []
        while True:
            # read progress when the socket is ready, wait at most 0.1 second
            readers, _, _ = select.select([prog], [], [], 0.1)
            for reader in readers:
                progress = t.ProgressMsg()
                reader.recv_into(progress)
                if progress.status in (
                    t.RecoveryStatus.RUN,
                    t.RecoveryStatus.SUCCESS,
                    t.RecoveryStatus.PROGRESS
                ) and progress_callback:
                    progress_callback(progress.nsteps, progress.cur_percent, progress.cur_step, dry_run)

            # every connection to control socket is terminated after response is sent, so for each
            # GET_STATUS request a new connection is needed
            status = get_status()

            desc = status.data.status.desc.decode(errors="ignore").strip()
            if description_filter(desc):
                description.append(desc)
                if status_callback:
                    status_callback(desc)

            # the update continues until IDLE status is reached
            # FAILURES may happen on the way but they don't necessarily mean a failed update - just errors
            # if the latest status is SUCCESS then an update is considered a success
            cur = status.data.status.current
            if cur == t.RecoveryStatus.SUCCESS:
                success = True
            elif cur == t.RecoveryStatus.FAILURE:
                success = False
            elif cur == t.RecoveryStatus.IDLE:
                return success, "\n".join(description)
