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
import threading
import time
from typing import Any, Callable, Iterator, List, Optional, Tuple
from unittest import mock

import pytest

from mpa.common.common import RESPONSE_FAILURE, RESPONSE_OK
from mpa.communication.common import ConflictingOperationInProgessError
from mpa.communication.daemon_transaction import DaemonTransaction

RESPONSE = f"{RESPONSE_OK} done"


class FakeTimer:
    """Timer which fires only on request (also after cancel(), to simulate timer firing concurrently with cancel())"""
    instances: List["FakeTimer"] = []

    def __init__(self, interval: float, function: Callable[[], None]) -> None:
        self.function = function
        self.cancelled = False
        FakeTimer.instances.append(self)

    def start(self) -> None:
        pass

    def cancel(self) -> None:
        self.cancelled = True


@pytest.fixture(autouse=True)
def fake_timer() -> Iterator[None]:
    FakeTimer.instances = []
    with mock.patch("mpa.communication.daemon_transaction.Timer", FakeTimer):
        yield


class FakeClient:
    def __init__(self, *, immediate_affirm_response: Optional[bytes] = None, broken: bool = False) -> None:
        self.immediate_affirm_response = immediate_affirm_response
        self.broken = broken
        self.affirm_handler: Optional[Callable[[Any], Optional[bool]]] = None
        self.responses: List[Tuple[str, Any]] = []

    def query(self, topic: str, message: Any = None, handler: Optional[Callable[[Any], Optional[bool]]] = None) -> None:
        if self.broken:
            raise RuntimeError("Missing subject in response to PING")
        self.affirm_handler = handler
        if self.immediate_affirm_response is not None:
            assert handler is not None
            handler(self.immediate_affirm_response)

    def respond(self, topic: str, response: Any, from_part: bytes, message_id: bytes) -> None:
        self.responses.append((topic, response))

    def affirm(self, affirmed: bool) -> None:
        assert self.affirm_handler is not None
        self.affirm_handler(b"true" if affirmed else b"false")


class FinalAction:
    def __init__(self, exc: Optional[Exception] = None) -> None:
        self.exc = exc
        self.calls: List[bool] = []
        self.threads: List[threading.Thread] = []

    def __call__(self, *, rollback: bool) -> None:
        self.calls.append(rollback)
        self.threads.append(threading.current_thread())
        if self.exc is not None:
            raise self.exc


def start_transaction(client: FakeClient, final_action: FinalAction, **kwargs: Any) -> DaemonTransaction:
    transaction = DaemonTransaction("Not confirmed", client, **kwargs)  # type: ignore[arg-type]
    transaction.start("test", final_action, b"from", b"id")
    transaction.set_response(RESPONSE, question="Keep it?")
    return transaction


def wait_until_finished(transaction: DaemonTransaction) -> None:
    deadline = time.monotonic() + 5
    while transaction.state is not DaemonTransaction.State.IDLE:
        assert time.monotonic() < deadline, "Transaction not finished in time"
        time.sleep(0.01)


def assert_rolled_back_response(client: FakeClient) -> None:
    assert len(client.responses) == 1
    topic, response = client.responses[0]
    assert topic == "test.resp"
    assert response.startswith(f"{RESPONSE_FAILURE} TransactionRolledBackError('Not confirmed')")


class TestDaemonTransaction:
    def test_affirmed(self) -> None:
        client, final_action = FakeClient(), FinalAction()
        transaction = start_transaction(client, final_action)
        client.affirm(True)
        assert final_action.calls == [False]
        assert client.responses == [("test.resp", RESPONSE)]
        assert transaction.state is DaemonTransaction.State.IDLE
        assert FakeTimer.instances[0].cancelled

    def test_rejected(self) -> None:
        client, final_action = FakeClient(), FinalAction()
        transaction = start_transaction(client, final_action)
        client.affirm(False)
        wait_until_finished(transaction)
        assert final_action.calls == [True]
        assert_rolled_back_response(client)
        assert transaction.last_transaction_rolled_back

    def test_rejection_rolls_back_outside_of_thread_handling_affirm_response(self) -> None:
        client, final_action = FakeClient(), FinalAction()
        transaction = start_transaction(client, final_action)
        client.affirm(False)
        wait_until_finished(transaction)
        assert final_action.threads[0] is not threading.current_thread()

    def test_timeout(self) -> None:
        client, final_action = FakeClient(), FinalAction()
        transaction = start_transaction(client, final_action)
        FakeTimer.instances[0].function()
        assert final_action.calls == [True]
        assert_rolled_back_response(client)
        assert transaction.state is DaemonTransaction.State.IDLE

    def test_timeout_after_affirm_does_nothing(self) -> None:
        client, final_action = FakeClient(), FinalAction()
        start_transaction(client, final_action)
        client.affirm(True)
        FakeTimer.instances[0].function()  # timer was already running when it was cancelled
        assert final_action.calls == [False]
        assert client.responses == [("test.resp", RESPONSE)]

    def test_affirm_after_timeout_does_nothing(self) -> None:
        client, final_action = FakeClient(), FinalAction()
        start_transaction(client, final_action)
        FakeTimer.instances[0].function()
        client.affirm(True)
        assert final_action.calls == [True]
        assert_rolled_back_response(client)

    def test_concurrent_timeout_during_affirmed_final_action_does_nothing(self) -> None:
        client = FakeClient()
        in_final_action, release_final_action = threading.Event(), threading.Event()
        calls: List[bool] = []

        def final_action(*, rollback: bool) -> None:
            calls.append(rollback)
            if not rollback:
                in_final_action.set()
                release_final_action.wait(5)

        start_transaction(client, final_action)  # type: ignore[arg-type]
        affirming = threading.Thread(target=client.affirm, args=(True,))
        affirming.start()
        assert in_final_action.wait(5)
        FakeTimer.instances[0].function()  # timer was already running when it was cancelled
        release_final_action.set()
        affirming.join(5)
        assert calls == [False]
        assert client.responses == [("test.resp", RESPONSE)]

    def test_responds_after_final_action(self) -> None:
        client = FakeClient()
        responses_seen_by_final_action: List[List[Tuple[str, Any]]] = []

        def final_action(*, rollback: bool) -> None:
            responses_seen_by_final_action.append(list(client.responses))

        start_transaction(client, final_action)  # type: ignore[arg-type]
        client.affirm(True)
        assert responses_seen_by_final_action == [[]]
        assert client.responses == [("test.resp", RESPONSE)]

    @pytest.mark.parametrize("affirmed", [True, False])
    def test_failure_of_final_action_is_responded(self, affirmed: bool) -> None:
        client, final_action = FakeClient(), FinalAction(RuntimeError("final action failed"))
        transaction = start_transaction(client, final_action)
        client.affirm(affirmed)
        wait_until_finished(transaction)
        assert len(client.responses) == 1
        assert client.responses[0][1].startswith(f"{RESPONSE_FAILURE} RuntimeError('final action failed')")

    def test_response_is_set_before_affirm_query_is_sent(self) -> None:
        # Affirm response can be handled in main thread before set_response() called from other thread returns
        client, final_action = FakeClient(immediate_affirm_response=b"true"), FinalAction()
        start_transaction(client, final_action)
        assert client.responses == [("test.resp", RESPONSE)]

    def test_commit(self) -> None:
        client, final_action = FakeClient(), FinalAction()
        transaction = start_transaction(client, final_action)
        assert transaction.commit()
        assert final_action.calls == [False]
        assert client.responses == []
        assert transaction.state is DaemonTransaction.State.IDLE
        assert not transaction.commit()

    def test_failed_commit_finishes_transaction(self) -> None:
        client, final_action = FakeClient(), FinalAction(RuntimeError("final action failed"))
        transaction = start_transaction(client, final_action)
        with pytest.raises(RuntimeError):
            transaction.commit()
        assert transaction.state is DaemonTransaction.State.IDLE
        FakeTimer.instances[0].function()
        assert final_action.calls == [False]

    def test_second_transaction_conflicts(self) -> None:
        client, final_action = FakeClient(), FinalAction()
        transaction = start_transaction(client, final_action)
        with pytest.raises(ConflictingOperationInProgessError):
            transaction.start("test", final_action, b"from", b"id")
