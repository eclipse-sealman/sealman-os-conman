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
from pathlib import Path

CHUNK_SIZE = 4096 * 32
IPC_MAGIC = 0x14052001
SWUPDATE_API_VERSION = 0x1
SOCKET_PROGRESS_PATH = Path("/tmp/swupdateprog")
SOCKET_IPC_PATH = Path("/tmp/sockinstctrl")
