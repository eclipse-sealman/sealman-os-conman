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
from typing import Any, Callable, Iterator, List, Tuple
from unittest import mock

import pytest

from mpa.common.common import RESPONSE_FAILURE, RESPONSE_OK
from mpa.communication.client import Async, background, guarded, sync


class InlineThread:
    """Runs target synchronously on start(), so tests need no joining"""
    def __init__(self, target: Callable[..., None], args: Tuple[Any, ...] = ()) -> None:
        self.target = target
        self.args = args

    def start(self) -> None:
        self.target(*self.args)


@pytest.fixture(autouse=True)
def inline_thread() -> Iterator[None]:
    with mock.patch("mpa.communication.client.KillerThread", InlineThread):
        yield


class Recorder:
    def __init__(self) -> None:
        self.responses: List[Tuple[Any, bytes, bytes]] = []
        self.post_responses: List[Any] = []

    def respond(self, response: Any, from_part: bytes, message_id: bytes) -> None:
        self.responses.append((response, from_part, message_id))

    def post_respond(self, response: Any) -> None:
        self.post_responses.append(response)


class TestBackground:
    def test_responds_with_return_value_of_sync_handler(self) -> None:
        recorder = Recorder()
        handler = background(guarded(sync(lambda message: {"echo": message.decode()})), recorder.respond,
                             post_respond=recorder.post_respond)
        assert isinstance(handler(b"hello", b"from", b"id"), Async)
        assert recorder.responses == [({"echo": "hello"}, b"from", b"id")]
        assert recorder.post_responses == [{"echo": "hello"}]

    def test_passes_request_ids_to_handler(self) -> None:
        recorder = Recorder()
        received: List[Tuple[bytes, bytes, bytes]] = []

        def handler(message: bytes, from_part: bytes, message_id: bytes) -> None:
            received.append((message, from_part, message_id))

        background(guarded(handler), recorder.respond)(b"msg", b"from", b"id")
        assert received == [(b"msg", b"from", b"id")]
        assert recorder.responses == [(RESPONSE_OK, b"from", b"id")]

    def test_does_not_respond_when_handler_returns_async(self) -> None:
        recorder = Recorder()
        handler = background(guarded(lambda message, from_part, message_id: Async()), recorder.respond,
                             post_respond=recorder.post_respond)
        handler(b"msg", b"from", b"id")
        assert recorder.responses == []
        assert recorder.post_responses == []

    def test_guarded_exception_is_sent_as_failure(self) -> None:
        recorder = Recorder()

        def handler(message: bytes, from_part: bytes, message_id: bytes) -> None:
            raise RuntimeError("boom")

        background(guarded(handler), recorder.respond)(b"msg", b"from", b"id")
        assert len(recorder.responses) == 1
        response, from_part, message_id = recorder.responses[0]
        assert response.startswith(RESPONSE_FAILURE)
        assert "boom" in response
        assert (from_part, message_id) == (b"from", b"id")
