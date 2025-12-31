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
from pathlib import Path
from time import sleep

# Local imports
from mpa.common.logger import Logger
from mpa.communication.common import SWUpdateError
from mpa.communication.inter_process_lock import InterProcessLock
from mpa.swupdate.swupdate_client import SWUpdateClient
from mpa.swupdate.swupdate_types import RecoveryStatus

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")

LOCK = InterProcessLock(Path("/tmp/swupdate.lock"))


def run_swupdate(filepath: Path) -> None:
    with LOCK.transaction("run_update"):
        c = SWUpdateClient()
        check_status = c.perform_update(Path(filepath), True, None)
        if check_status and check_status == RecoveryStatus.SUCCESS:
            sleep(5)
            update_status = c.perform_update(Path(filepath), False, None)
            if update_status != RecoveryStatus.SUCCESS:
                raise SWUpdateError("Image install fail")
        else:
            raise SWUpdateError("Image check fail")
