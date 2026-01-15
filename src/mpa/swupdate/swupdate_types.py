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

MAX_IMAGE_NAME_LEN = 256
MAX_HANDLER_NAME_LEN = 64
MAX_INFO_LEN = 2048
MAX_MSG_LEN = 128
MAX_KEY_ASCII_LEN = 65
MAX_IVT_ASCII_LEN = 33
MAX_VERSION_LEN = 256
MAX_VAR_LEN = 256


class RecoveryStatus(IntEnum):
    IDLE = 0
    START = 1
    RUN = 2
    SUCCESS = 3
    FAILURE = 4
    DOWNLOAD = 5
    DONE = 6
    SUBPROCESS = 7
    PROGRESS = 8


class SourceType(IntEnum):
    SOURCE_UNKNOWN = 0
    SOURCE_WEBSERVER = 1
    SOURCE_SURICATTA = 2
    SOURCE_DOWNLOADER = 3
    SOURCE_LOCAL = 4
    SOURCE_CHUNKS_DOWNLOADER = 5


class MsgType(IntEnum):
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


class Command(IntEnum):
    ACTIVATION = 0
    CONFIG = 1
    ENABLE = 2
    GET_STATUS = 3
    SET_DOWNLOAD_URL = 4


class RunType(IntEnum):
    DEFAULT = 0
    DRY_RUN = 1
    INSTALL = 2


class ProgressMsg(ctypes.Structure):
    _fields_ = [
        ("apiversion", ctypes.c_uint),
        ("status", ctypes.c_int),          # RecoveryStatus
        ("dwl_percent", ctypes.c_uint),
        ("dwl_bytes", ctypes.c_ulonglong),
        ("nsteps", ctypes.c_uint),
        ("cur_step", ctypes.c_uint),
        ("cur_percent", ctypes.c_uint),
        ("cur_image", ctypes.c_char * MAX_IMAGE_NAME_LEN),
        ("hnd_name", ctypes.c_char * MAX_HANDLER_NAME_LEN),
        ("source", ctypes.c_int),          # SourceType
        ("infolen", ctypes.c_uint),
        ("info", ctypes.c_char * MAX_INFO_LEN),
    ]


class SwUpdateRequest(ctypes.Structure):
    _fields_ = [
        ("apiversion", ctypes.c_uint),
        ("source", ctypes.c_int),           # SourceType
        ("dry_run", ctypes.c_int),          # RunType
        ("len", ctypes.c_size_t),
        ("info", ctypes.c_char * 512),
        ("software_set", ctypes.c_char * MAX_VERSION_LEN),
        ("running_mode", ctypes.c_char * MAX_VERSION_LEN),
        ("disable_store_swu", ctypes.c_uint8),  # safer than c_bool
    ]


class Status(ctypes.Structure):
    _fields_ = [
        ("current", ctypes.c_int),
        ("last_result", ctypes.c_int),
        ("error", ctypes.c_int),
        ("desc", ctypes.c_char * MAX_INFO_LEN),
    ]


class Notify(ctypes.Structure):
    _fields_ = [
        ("status", ctypes.c_int),
        ("error", ctypes.c_int),
        ("level", ctypes.c_int),
        ("msg", ctypes.c_char * MAX_INFO_LEN),
    ]


class InstMsg(ctypes.Structure):
    _fields_ = [
        ("req", SwUpdateRequest),
        ("len", ctypes.c_uint),
        ("buf", ctypes.c_char * MAX_INFO_LEN),
    ]


class ProcMsg(ctypes.Structure):
    _fields_ = [
        ("source", ctypes.c_int),
        ("cmd", ctypes.c_int),              # Command
        ("timeout", ctypes.c_int),
        ("len", ctypes.c_uint),
        ("buf", ctypes.c_char * MAX_INFO_LEN),
    ]


class AesKeyMsg(ctypes.Structure):
    _fields_ = [
        ("key_ascii", ctypes.c_char * MAX_KEY_ASCII_LEN),
        ("ivt_ascii", ctypes.c_char * MAX_IVT_ASCII_LEN),
    ]


class Versions(ctypes.Structure):
    _fields_ = [
        ("minimum_version", ctypes.c_char * MAX_VERSION_LEN),
        ("maximum_version", ctypes.c_char * MAX_VERSION_LEN),
        ("current_version", ctypes.c_char * MAX_VERSION_LEN),
    ]


class Revisions(ctypes.Structure):
    _fields_ = [
        ("boardname", ctypes.c_char * MAX_VERSION_LEN),
        ("revision", ctypes.c_char * MAX_VERSION_LEN),
    ]


class Vars(ctypes.Structure):
    _fields_ = [
        ("varnamespace", ctypes.c_char * MAX_VAR_LEN),
        ("varname", ctypes.c_char * MAX_VAR_LEN),
        ("varvalue", ctypes.c_char * MAX_VAR_LEN),
    ]


class MsgData(ctypes.Union):
    _fields_ = [
        ("msg", ctypes.c_char * MAX_MSG_LEN),
        ("status", Status),
        ("notify", Notify),
        ("instmsg", InstMsg),
        ("procmsg", ProcMsg),
        ("aeskeymsg", AesKeyMsg),
        ("versions", Versions),
        ("revisions", Revisions),
        ("vars", Vars),
    ]


class IpcMessage(ctypes.Structure):
    _fields_ = [
        ("magic", ctypes.c_int),
        ("type", ctypes.c_int),     # MsgType
        ("data", MsgData),
    ]
