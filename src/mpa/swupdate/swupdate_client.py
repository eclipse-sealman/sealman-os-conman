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
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from socket import AF_UNIX, SOCK_CLOEXEC, SOCK_STREAM, socket
from typing import Any, Optional

# Local imports
import mpa.swupdate.swupdate_types as swupdate_types
from mpa.common.logger import Logger
from mpa.communication.common import SWUpdateError
from mpa.swupdate.swupdate_consts import (
    CHUNK_SIZE,
    IPC_MAGIC,
    SOCKET_IPC_PATH,
    SOCKET_PROGRESS_PATH,
)

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")

# type SWUpdateCallback = Callable[[dict[str, Any]], None]


class SWUpdateClient():
    control_socket: Optional[socket]
    progress_socket: Optional[socket]
    update_status: Optional[int]

    def __connect_to_sockets(self) -> None:
        self.control_socket = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC)
        self.control_socket.connect(str(SOCKET_IPC_PATH))
        self.progress_socket = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC)
        self.progress_socket.connect(str(SOCKET_PROGRESS_PATH))

    def __cleanup_connections(self) -> None:
        if self.control_socket:
            self.control_socket.close()
        if self.progress_socket:
            self.progress_socket.close()

    def __status_thread(self, status_callback: Callable[[dict[str, Any]], None]) -> None:
        while True:
            if not self.control_socket:
                self.control_socket = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC)
                self.control_socket.connect(str(SOCKET_IPC_PATH))
            ipc_request = self.__make_getstatus_ipc_request()

            try:
                self.control_socket.send(ipc_request)
                recvie_message = self.control_socket.recv(swupdate_types.IPC_MSG_SIZE)
                if len(recvie_message) != swupdate_types.IPC_MSG_SIZE:
                    continue
            except Exception:
                self.control_socket = None
                continue

            ipc_response = swupdate_types.IpcMessage.from_buffer_copy(recvie_message)
            if len(ipc_response.data.status.desc) > 0:
                status_data = {
                    "type": "status",
                    "dry_run": self.dry_run,
                    "data": {
                        "current": ipc_response.data.status.current,
                        "last_result": ipc_response.data.status.last_result,
                        "error": str(ipc_response.data.status.error),
                        "desc": str(ipc_response.data.status.desc)
                    }
                }
                if status_callback is not None:
                    status_callback(status_data)

            if ipc_response.data.status.current == swupdate_types.RecoveryStatus.IDLE:
                break

    def __progress_thread(self, progress_callback: Callable[[dict[str, Any]], None]) -> None:
        current_status = -1
        while True:
            try:
                if self.progress_socket:
                    data = self.progress_socket.recv(swupdate_types.PROGRESS_MSG_SIZE)
                    if len(data) != swupdate_types.PROGRESS_MSG_SIZE:
                        logger.debug("Wrong size of msg")
                        continue
                    ipc_progress = swupdate_types.ProgressMsg.from_buffer_copy(data)
                    progress_data = {
                        "type": "progress",
                        "dry_run": self.dry_run,
                        "data": {
                            "apiversion": ipc_progress.apiversion,
                            "nsteps": ipc_progress.nsteps,
                            "cur_step": ipc_progress.cur_step,
                            "cur_percent": ipc_progress.cur_percent,
                            "info": str(ipc_progress.info)
                        }
                    }
                    if progress_callback is not None:
                        progress_callback(progress_data)
                    if current_status != ipc_progress.status.value:
                        logger.debug(f"New status: {ipc_progress.status.value}, previous status: {current_status}")
                        current_status = ipc_progress.status.value
                    if current_status == swupdate_types.RecoveryStatus.FAILURE:
                        self.update_status = current_status
                        break
                    if current_status == swupdate_types.RecoveryStatus.SUCCESS:
                        self.update_status = current_status
                        break
            except BlockingIOError:
                pass

    def __make_ipc_request(self, request_type: swupdate_types.MsgType,
                           request_data: swupdate_types.MsgData) -> swupdate_types.IpcMessage:
        ipc_request = swupdate_types.IpcMessage()
        ipc_request.magic = IPC_MAGIC
        ipc_request.type = request_type
        ipc_request.data = request_data
        return ipc_request

    def __make_install_ipc_request(self, dry_run: bool) -> swupdate_types.IpcMessage:
        sw_update_req = swupdate_types.SwUpdateRequest(
            apiversion=1,
            source=0,
            dry_run=swupdate_types.RunType.RUN_DRYRUN if dry_run else swupdate_types.RunType.RUN_INSTALL,
            len=0,
            info=b"",
            software_set=b"",
            running_mode=b"",
            disable_store_swu=False
        )
        msg_data = swupdate_types.MsgData()
        msg_data.instmsg = swupdate_types.InstMsg(req=sw_update_req, len=0, buf=b"")

        return self.__make_ipc_request(swupdate_types.MsgType(swupdate_types.MsgType.REQ_INSTALL), msg_data)

    def __make_getstatus_ipc_request(self) -> swupdate_types.IpcMessage:
        msg_data = swupdate_types.MsgData()
        return self.__make_ipc_request(swupdate_types.MsgType(swupdate_types.MsgType.GET_STATUS), msg_data)

    def __send_data(self, data: bytes) -> None:
        if self.control_socket:
            self.control_socket.sendall(data)

    def perform_update(self, path_to_swu: Path, dry_run: bool,
                       progress_callback: Optional[Callable[[dict[str, Any]], None]]) -> Optional[int]:
        self.update_status = None
        self.dry_run = dry_run
        if not path_to_swu.exists():
            raise SWUpdateError("Provided software update file does not exists!")

        self.__connect_to_sockets()

        self.progress_thread = threading.Thread(target=self.__progress_thread, daemon=True, args=(progress_callback,))
        self.progress_thread.start()
        install_request = self.__make_install_ipc_request(dry_run)
        if self.control_socket:
            sent_bytes = self.control_socket.send(install_request)
            recvie_message = self.control_socket.recv(swupdate_types.IPC_MSG_SIZE)
        else:
            raise SWUpdateError("Could not connect to IPC socket")

        ipc_response = swupdate_types.IpcMessage.from_buffer_copy(recvie_message)
        if ipc_response.type == swupdate_types.MsgType.NACK:
            raise SWUpdateError("Software update already in progress")

        swu_size = path_to_swu.stat().st_size
        logger.debug(f"Software update file size: {swu_size}, chunk size: {CHUNK_SIZE}")

        with path_to_swu.open("rb") as swu_data:
            sent_bytes = 0
            while chunk := swu_data.read(CHUNK_SIZE * 12):
                try:
                    self.__send_data(chunk)
                except BrokenPipeError:
                    logger.debug("SWUpdate rejects chunks")
                    break
                sent_bytes += len(chunk)

        logger.debug("Image sent to SWUpdate, waiting for results...")
        if self.control_socket:
            self.control_socket.close()
            self.control_socket = None
        self.status_thread = threading.Thread(target=self.__status_thread, daemon=True, args=(progress_callback,))
        self.status_thread.start()
        self.progress_thread.join()
        self.status_thread.join()
        logger.info(f"Update status: {str(self.update_status)}")
        self.__cleanup_connections()

        return self.update_status
