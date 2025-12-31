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
import ctypes
from enum import IntEnum


class SwupdateDaemonMessages(IntEnum):
    INFO = 0
    SUCCESS = 1
    ERROR = 2


class RecoveryStatus(ctypes.c_int):
    UNKNOWN = 1
    IDLE = 0
    START = 1
    RUN = 2
    SUCCESS = 3
    FAILURE = 4
    DOWNLOAD = 5
    DONE = 6
    SUBPROCESS = 7
    PROGRESS = 8


class SourceType(ctypes.c_int):
    SOURCE_UNKNOWN = 0
    SOURCE_WEBSERVER = 1
    SOURCE_SURICATTA = 2
    SOURCE_DOWNLOADER = 3
    SOURCE_LOCAL = 4
    SOURCE_CHUNKS_DOWNLOADER = 5


class ProgressMsg(ctypes.Structure):
    _fields_ = [
        ("apiversion", ctypes.c_uint),
        ("status", RecoveryStatus),
        ("dwl_percent", ctypes.c_uint),
        ("dwl_bytes", ctypes.c_ulonglong),
        ("nsteps", ctypes.c_uint),
        ("cur_step", ctypes.c_uint),
        ("cur_percent", ctypes.c_uint),
        ("cur_image", ctypes.c_char * 256),
        ("hnd_name", ctypes.c_char * 64),
        ("source", SourceType),
        ("infolen", ctypes.c_uint),
        ("info", ctypes.c_char * 2048),
    ]


PROGRESS_MSG_SIZE = ctypes.sizeof(ProgressMsg)


class MsgType(ctypes.c_int):
    REQ_INSTALL = 0
    ACK = 1
    NACK = 2
    GET_STATUS = 3
    POST_UPDATE = 4
    SWUPDATE_SUBPROCESS = 5
    SET_AES_KEY = 6
    SET_UPDATE_STATE = 7
    GET_UPDATE_STATE = 8
    REQ_INSTALL_EXT = 9
    SET_VERSIONS_RANGE = 10
    NOTIFY_STREAM = 11
    GET_HW_REVISION = 12
    SET_SWUPDATE_VARS = 13
    GET_SWUPDATE_VARS = 14


class Command(ctypes.c_int):
    CMD_ACTIVATION = 0
    CMD_CONFIG = 1
    CMD_ENABLE = 2
    CMD_GET_STATUS = 3
    CMD_SET_DOWNLOAD_URL = 4


class RunType(ctypes.c_int):
    RUN_DEFAULT = 0
    RUN_DRYRUN = 1
    RUN_INSTALL = 2


class SwUpdateRequest(ctypes.Structure):
    _fields_ = [
        ("apiversion", ctypes.c_uint),
        ("source", SourceType),
        ("dry_run", RunType),
        ("len", ctypes.c_size_t),
        ("info", ctypes.c_char * 512),
        ("software_set", ctypes.c_char * 256),
        ("running_mode", ctypes.c_char * 256),
        ("disable_store_swu", ctypes.c_bool)
    ]


class Status(ctypes.Structure):
    _fields_ = [
        ("current", ctypes.c_int),
        ("last_result", ctypes.c_int),
        ("error", ctypes.c_int),
        ("desc", ctypes.c_char * 2048)
    ]


class Notify(ctypes.Structure):
    _fields_ = [
        ("status", ctypes.c_int),
        ("error", ctypes.c_int),
        ("level", ctypes.c_int),
        ("msg", ctypes.c_char * 2048)
    ]


class InstMsg(ctypes.Structure):
    _fields_ = [
        ("req", SwUpdateRequest),
        ("len", ctypes.c_uint),
        ("buf", ctypes.c_char * 2048)
    ]


class ProcMsg(ctypes.Structure):
    _fields_ = [
        ("source", ctypes.c_int),
        ("cmd", ctypes.c_int),
        ("timeout", ctypes.c_int),
        ("len", ctypes.c_uint),
        ("buf", ctypes.c_char * 2048)
    ]


class AesKeyMsg(ctypes.Structure):
    _fields_ = [
        ("key_ascii", ctypes.c_char * 65),
        ("ivt_ascii", ctypes.c_char * 33)
    ]


class Versions(ctypes.Structure):
    _fields_ = [
        ("minimum_version", ctypes.c_char * 256),
        ("maximum_version", ctypes.c_char * 256),
        ("current_version", ctypes.c_char * 256)
    ]


class Revisions(ctypes.Structure):
    _fields_ = [
        ("boardname", ctypes.c_char * 256),
        ("revision", ctypes.c_char * 256)
    ]


class Vars(ctypes.Structure):
    _fields_ = [
        ("varnamespace", ctypes.c_char * 256),
        ("varname", ctypes.c_char * 256),
        ("varvalue", ctypes.c_char * 256)
    ]


class MsgData(ctypes.Union):
    _fields_ = [
        ("msg", ctypes.c_char * 128),
        ("status", Status),
        ("notify", Notify),
        ("instmsg", InstMsg),
        ("procmsg", ProcMsg),
        ("aeskeymsg", AesKeyMsg),
        ("versions", Versions),
        ("revisions", Revisions),
        ("vars", Vars)
    ]


class IpcMessage(ctypes.Structure):
    _fields_ = [
        ("magic", ctypes.c_int),
        ("type", ctypes.c_int),
        ("data", MsgData)
    ]


IPC_MSG_SIZE = ctypes.sizeof(IpcMessage)
