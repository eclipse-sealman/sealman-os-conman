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
"""
Simple lockfile based mechanism to ensure serialization of some actions within
single process as well as between multiple processes. There is also ability to
steal lock from another process in exceptional cases.
"""
from __future__ import annotations

# Standard imports
import os
import time
from contextlib import contextmanager
from pathlib import Path
from threading import Lock
from typing import Callable, Iterator, Optional

# Local imports
from mpa.common.logger import Logger
from mpa.communication.common import ConflictingOperationInProgessError
from mpa.communication.process import run_command_unchecked
from mpa.communication.status_codes import SUCCESS

logger = Logger(__name__)


class InterProcessLock:
    NOT_ACQUIRED = "not acquired"

    def __init__(self, lockfile: Path, post_lock_checker: Optional[Callable[[], None]] = None,
                 *, stale_lock_seconds: Optional[int] = None):
        self.lockfile = lockfile
        self.post_lock_checker = post_lock_checker
        self.thread_lock = Lock()
        self.stale_lock_seconds = stale_lock_seconds

    def __try_lock_externally(self) -> bool:
        result = run_command_unchecked("lockfile-create", "--retry", "0", "--lock-name", self.lockfile)
        if result.returncode == SUCCESS:
            return True
        if self.stale_lock_seconds:
            if time.time() - self.lockfile.stat().st_mtime > self.stale_lock_seconds:
                self.lockfile.unlink(missing_ok=False)
            result = run_command_unchecked("lockfile-create", "--retry", "0", "--lock-name", self.lockfile)
            if result.returncode == SUCCESS:
                return True
        return False

    def __lock_externally(self, description: str) -> None:
        try:
            if self.__try_lock_externally():
                self.lockfile.write_text(f"{os.getpid()} {time.time()} {description}")
            else:
                desc = "missing details"
                try:
                    desc = self.lockfile.read_text()
                except Exception:
                    pass
                raise ConflictingOperationInProgessError("Another process performs conflicting operation", desc)
        except Exception:
            self.thread_lock.release()
            raise

    def __try_unlocking_externally(self) -> Optional[str]:
        result = run_command_unchecked("lockfile-create", "--retry", "0", "--lock-name", self.lockfile)
        if result.returncode == SUCCESS:
            self.lockfile.unlink(missing_ok=False)
            return self.NOT_ACQUIRED
        result = run_command_unchecked("lockfile-touch", "--oneshot", "--lock-name", self.lockfile)
        if result.returncode != SUCCESS:
            return "not touchable"
        try:
            desc = self.lockfile.read_text()
        except Exception as exc:
            logger.exception(exc)
            return "not readable"
        pid, space, rest = desc.partition(" ")
        if pid != str(os.getpid()):
            return f"acquired by {desc}"
        self.lockfile.unlink(missing_ok=False)
        return None

    def __unlock_all(self) -> None:
        try:
            unlock_error = self.__try_unlocking_externally()
            if unlock_error is not None:
                raise RuntimeError(f"On release lock was {unlock_error}")
        finally:
            self.thread_lock.release()

    def __lock_internally(self) -> None:
        if not self.thread_lock.acquire(timeout=1):
            try:
                desc = self.lockfile.read_text()
            except Exception:
                raise RuntimeError(f"Timeout on thread lock guarding {self.lockfile}")
            raise ConflictingOperationInProgessError("We are currently perfoming conflicting operation", desc)

    def set_post_lock_checker(self, post_lock_checker: Callable[[], None]) -> None:
        if self.post_lock_checker is not None:
            # Programming error, we don't excepct overriding # post_lock_checker...
            raise RuntimeError("Post lock checker is already set")
        self.post_lock_checker = post_lock_checker

    @contextmanager
    def stolen_lock(self, description: str) -> Iterator[None]:
        self.__lock_internally()
        try:
            unlock_error = self.__try_unlocking_externally()
            if unlock_error != self.NOT_ACQUIRED:
                logger.warning(f"While performing cleanup lock was {unlock_error}")
        except Exception as exc:
            logger.error("Unexpected exception from __try_unlocking_externally() will be consumed")
            logger.exception(exc)
        finally:
            self.lockfile.unlink(missing_ok=True)
        self.__lock_externally(description)
        try:
            # stolen lock is not executing post_lock_checker, as we expect it to
            # fail because we potentially stole the lock from other process
            yield None
        finally:
            self.__unlock_all()

    @contextmanager
    def transaction(self, description: str, *, already_locked: bool = False) -> Iterator[None]:
        # We allow consious recursive execution --- i.e. if already_locked is True
        # we do nothing but ensuring this really is recursive call
        if already_locked:
            if not self.thread_lock.locked():
                raise RuntimeError(f"Lock guarding {self.lockfile} was not held")
            yield None
            return
        # Actual real locking
        self.__lock_internally()
        self.__lock_externally(description)
        try:
            if self.post_lock_checker is not None:
                self.post_lock_checker()
            yield None
        finally:
            self.__unlock_all()
