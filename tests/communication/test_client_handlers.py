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
from typing import List, Optional, Tuple, Union

from mpa.communication.client import Client

TOPIC = "something.resp"


class Handler:
    """Query handler which persists (or not) after missing response indication"""
    def __init__(self, persisting: bool) -> None:
        self.persisting = persisting
        self.messages: List[Union[bytes, str]] = []

    def __call__(self, message: Union[bytes, str]) -> Optional[bool]:
        self.messages.append(message)
        return self.persisting if isinstance(message, str) else None


def add(handlers: Client.Handlers, sequence: int, persisting: bool) -> Tuple[Handler, Client.QueryHandler]:
    handler = Handler(persisting)
    _is_new, query_handler = handlers.add_query_handler(TOPIC, handler)
    query_handler.add_id(Client.QueryId(b"pub\0\0\0\0\0", sequence))
    return handler, query_handler


def lost_response(sequence: int) -> Client.LostRequest:
    return Client.LostRequest(sequence, "something.req", TOPIC)


def lost_request(sequence: int) -> Client.LostRequest:
    return Client.LostRequest(sequence, "something.req", "")


class TestLostRequests:
    def test_persisting_handler_stays_registered(self) -> None:
        handlers = Client.Handlers()
        handler, query_handler = add(handlers, 1, persisting=True)
        assert handlers.inform_query_handlers_about_lost_response(lost_response(1)) == (True, None)
        assert len(handler.messages) == 1
        assert handlers.query[TOPIC] == {query_handler}

    def test_other_handlers_of_topic_stay_registered(self) -> None:
        handlers = Client.Handlers()
        add(handlers, 1, persisting=False)
        _handler, other = add(handlers, 2, persisting=False)
        assert handlers.inform_query_handlers_about_lost_response(lost_response(1)) == (True, None)
        assert handlers.query[TOPIC] == {other}

    def test_last_handler_removal_requests_unsubscription(self) -> None:
        handlers = Client.Handlers()
        add(handlers, 1, persisting=False)
        assert handlers.inform_query_handlers_about_lost_response(lost_response(1)) == (True, TOPIC)
        assert TOPIC not in handlers.query

    def test_last_handler_removal_keeps_subscription_needed_by_other_handlers(self) -> None:
        handlers = Client.Handlers()
        handlers.add_trivial_handler(TOPIC, lambda message: None)
        add(handlers, 1, persisting=False)
        assert handlers.inform_query_handlers_about_lost_response(lost_response(1)) == (True, None)
        assert TOPIC not in handlers.query

    def test_lost_request_without_response_topic_is_matched_by_sequence(self) -> None:
        handlers = Client.Handlers()
        _handler, kept = add(handlers, 1, persisting=False)
        handler, _query_handler = add(handlers, 2, persisting=False)
        assert handlers.inform_query_handlers_about_lost_response(lost_request(2)) == (True, None)
        assert handler.messages and isinstance(handler.messages[0], str)
        assert handlers.query[TOPIC] == {kept}

    def test_unknown_lost_request_is_not_handled(self) -> None:
        handlers = Client.Handlers()
        add(handlers, 1, persisting=False)
        assert handlers.inform_query_handlers_about_lost_response(lost_response(7)) == (False, None)
        assert handlers.inform_query_handlers_about_lost_response(lost_request(7)) == (False, None)
        assert len(handlers.query[TOPIC]) == 1
