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
import json
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterator, List, Optional, Tuple
from unittest import mock

import pytest

import mpa.communication.topics as topics
from mpa.common.common import RESPONSE_FAILURE, RESPONSE_OK
from mpa.communication.common import MissingRollbackDataError, PendingRollbackError
from mpa.config.common import CONFIG_FORMAT_VERSION
from mpa.device import device_config
from mpa.device.device_config import SetConfig

CURRENT_CONFIG = {"config_format_version": CONFIG_FORMAT_VERSION, "motd": "current motd"}
BACKUP_CONFIG = {"config_format_version": CONFIG_FORMAT_VERSION, "motd": "old motd"}
UNUSABLE_BACKUPS = ["{", json.dumps("FAILURE get_config failed"), json.dumps({"motd": "missing config_format_version"})]


class FakeTimer:
    """Timer which fires only on request"""
    instances: List["FakeTimer"] = []

    def __init__(self, interval: float, function: Callable[[], None]) -> None:
        self.function = function
        FakeTimer.instances.append(self)

    def start(self) -> None:
        pass

    def cancel(self) -> None:
        pass


class FakeClient:
    """
    Daemons respond immediately (OK, or CURRENT_CONFIG to get_config), unless communication is broken; affirm handler
    is kept for the test; queries, responses and sent messages are recorded
    """
    def __init__(self, *, broken_affirm: bool = False, broken: bool = False, broken_get_config: bool = False) -> None:
        self.broken_affirm = broken_affirm
        self.broken = broken
        self.broken_get_config = broken_get_config
        self.sent: List[Tuple[str, Any]] = []
        self.affirm_handler: Optional[Callable[[Any], Optional[bool]]] = None
        self.events: List[Tuple[str, str]] = []
        self.query_threads: List[threading.Thread] = []
        self.response: Any = None

    def send(self, topic: str, message: Any = None) -> None:
        self.sent.append((topic, message))

    def query(self, topic: str, message: Any = None, handler: Optional[Callable[[Any], Optional[bool]]] = None) -> None:
        assert handler is not None
        if topic.startswith("affirm."):
            if self.broken_affirm:
                raise RuntimeError("Missing subject in response to PING")
            self.affirm_handler = handler
            return
        if self.broken:
            raise RuntimeError("Missing subject in response to PING")
        self.events.append(("query", topic))
        self.query_threads.append(threading.current_thread())
        if topic == topics.dev.get_config:
            handler(json.dumps(f"{RESPONSE_FAILURE} get_config failed" if self.broken_get_config else CURRENT_CONFIG).encode())
            return
        handler(json.dumps(RESPONSE_OK).encode())

    def respond(self, topic: str, response: Any, from_part: bytes, message_id: bytes) -> None:
        self.events.append(("respond", topic))
        self.response = response

    def affirm(self, affirmed: bool) -> None:
        assert self.affirm_handler is not None
        self.affirm_handler(b"true" if affirmed else b"false")

    def wait_for_response(self) -> None:
        deadline = time.monotonic() + 5
        while self.response is None:
            assert time.monotonic() < deadline, "No response in time"
            time.sleep(0.01)


@pytest.fixture
def backup(tmp_path: Path) -> Iterator[Path]:
    FakeTimer.instances = []
    backup = tmp_path / "device_config.back"
    backup.write_text(json.dumps(BACKUP_CONFIG))
    with mock.patch.object(device_config, "DEVICE_BACKUP_CONFIG", backup), \
         mock.patch("mpa.communication.daemon_transaction.Timer", FakeTimer):
        yield backup


def set_config(client: FakeClient) -> SetConfig:
    return SetConfig(client, mock.Mock())  # type: ignore[arg-type]


def confirm_config(client: FakeClient) -> threading.Event:
    return set_config(client).confirm_config(b"from", b"id")


class TestConfirmConfig:
    def test_rejection_rolls_back_before_responding(self, backup: Path) -> None:
        client = FakeClient()
        event = confirm_config(client)
        client.affirm(False)
        assert event.wait(5)
        client.wait_for_response()
        assert client.events == [("query", topics.dev.motd.set_config), ("respond", "dev.set_config.resp")]
        assert client.response.startswith(f"{RESPONSE_FAILURE} TransactionRolledBackError")
        assert not backup.exists()

    def test_rejection_rolls_back_outside_of_thread_handling_affirm_response(self, backup: Path) -> None:
        # Rollback waits for responses of other daemons, which are received by main thread
        client = FakeClient()
        event = confirm_config(client)
        client.affirm(False)
        assert event.wait(5)
        assert client.query_threads[0] is not threading.current_thread()

    def test_timeout_rolls_back_before_responding(self, backup: Path) -> None:
        client = FakeClient()
        event = confirm_config(client)
        FakeTimer.instances[0].function()
        assert event.is_set()
        assert client.events == [("query", topics.dev.motd.set_config), ("respond", "dev.set_config.resp")]
        assert not backup.exists()

    def test_affirmation_removes_backup(self, backup: Path) -> None:
        client = FakeClient()
        event = confirm_config(client)
        client.affirm(True)
        assert event.is_set()
        assert client.events == [("respond", "dev.set_config.resp")]
        assert client.response.startswith(f"{RESPONSE_OK} Confirmation received")
        assert not backup.exists()

    def test_failure_to_ask_for_affirmation_is_rolled_back_by_timeout(self, backup: Path) -> None:
        # Exception is eaten, so the only response is sent by transaction after timer rolled back
        client = FakeClient(broken_affirm=True)
        event = confirm_config(client)
        assert not event.is_set()
        assert client.events == []
        FakeTimer.instances[0].function()
        assert event.is_set()
        assert client.events == [("query", topics.dev.motd.set_config), ("respond", "dev.set_config.resp")]
        assert client.response.startswith(f"{RESPONSE_FAILURE} TransactionRolledBackError")
        assert not backup.exists()

    def test_failed_rollback_is_responded_as_pending_rollback(self, backup: Path) -> None:
        client = FakeClient(broken=True)
        event = confirm_config(client)
        FakeTimer.instances[0].function()
        assert event.is_set()
        assert client.response.startswith(f"{RESPONSE_FAILURE} PendingRollbackError")
        assert json.loads(backup.read_text()) == BACKUP_CONFIG


class TestPrepareBackupConfig:
    def test_stores_current_config(self, backup: Path) -> None:
        backup.unlink()
        set_config(FakeClient()).prepare_backup_config()
        assert json.loads(backup.read_text()) == CURRENT_CONFIG

    def test_keeps_pending_rollback(self, backup: Path) -> None:
        # Current config may be partially applied by previous failed set_config
        client = FakeClient()
        set_config(client).prepare_backup_config()
        assert client.events == []
        assert json.loads(backup.read_text()) == BACKUP_CONFIG
        assert client.sent[-1][0] == "dev.set_config.rt"

    @pytest.mark.parametrize("content", UNUSABLE_BACKUPS)
    def test_replaces_unusable_pending_rollback(self, backup: Path, content: str) -> None:
        backup.write_text(content)
        set_config(FakeClient()).prepare_backup_config()
        assert json.loads(backup.read_text()) == CURRENT_CONFIG


class TestRollbackConfig:
    def test_removes_backup_after_applying_it(self, backup: Path) -> None:
        client = FakeClient()
        set_config(client).rollback_config()
        assert client.events == [("query", topics.dev.motd.set_config)]
        assert not backup.exists()

    def test_keeps_backup_as_pending_rollback_if_it_cannot_be_applied(self, backup: Path) -> None:
        with pytest.raises(PendingRollbackError):
            set_config(FakeClient(broken=True)).rollback_config()
        assert json.loads(backup.read_text()) == BACKUP_CONFIG

    @pytest.mark.parametrize("content", UNUSABLE_BACKUPS)
    def test_removes_unusable_backup(self, backup: Path, content: str) -> None:
        backup.write_text(content)
        client = FakeClient()
        with pytest.raises(MissingRollbackDataError):
            set_config(client).rollback_config()
        assert client.events == []
        assert not backup.exists()
        assert client.sent[-1][0] == "dev.set_config.rt"
