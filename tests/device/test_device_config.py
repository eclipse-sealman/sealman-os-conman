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
from mpa.device import device_config
from mpa.device.device_config import SetConfig


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
    """Daemons respond OK immediately, affirm handler is kept for the test, queries and responses are recorded"""
    def __init__(self, *, broken_affirm: bool = False) -> None:
        self.broken_affirm = broken_affirm
        self.affirm_handler: Optional[Callable[[Any], Optional[bool]]] = None
        self.events: List[Tuple[str, str]] = []
        self.query_threads: List[threading.Thread] = []
        self.response: Any = None

    def send(self, topic: str, message: Any = None) -> None:
        pass

    def query(self, topic: str, message: Any = None, handler: Optional[Callable[[Any], Optional[bool]]] = None) -> None:
        assert handler is not None
        if topic.startswith("affirm."):
            if self.broken_affirm:
                raise RuntimeError("Missing subject in response to PING")
            self.affirm_handler = handler
            return
        self.events.append(("query", topic))
        self.query_threads.append(threading.current_thread())
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
    backup.write_text(json.dumps({"motd": "old motd"}))
    with mock.patch.object(device_config, "DEVICE_BACKUP_CONFIG", backup), \
         mock.patch("mpa.communication.daemon_transaction.Timer", FakeTimer):
        yield backup


def confirm_config(client: FakeClient) -> threading.Event:
    return SetConfig(client, mock.Mock()).confirm_config(b"from", b"id")  # type: ignore[arg-type]


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
