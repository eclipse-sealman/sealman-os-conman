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
Class which sends request to confirm and depending on contents of response
(or lack of response) performs commit or rollback action.

Such behaviour was initially intended for cases where some change could break
connectivity between EG and user hence we want to ensure, that user still has
access to the device after it was applied (e.g. network config change may break)

Example sequence of events in positive case:

DAEMON advertise handling: do_something_dangerous.req
CLI    advertise handling: affirm.do_something_dangerous.req
       send:               do_something_dangerous.req
DAEMON receive:            do_something_dangerous.req
       exec:               dt = DaemonTransaction("Failed to perform something dangerous",...)
                           dt.start("do_something_dangeorus", function_to_call_at_the_end_of_transaction, cli_request_metadata)
                           do something dangerous (sucesfully)
                           dt.set_response("dangerous thing suceeded")
       send (by dt):       affirm.do_something_dangeours.req
CLI    receive:            affirm.do_something_dangeours.req
                           ask user to confirm (this may go over network, so if connectivity is broken user will not see
                           it, but this time all is ok, so users confirms)
       send:               affirm.do_something_dangerous.resp
DAEMON receive:            affirm.do_something_dangerous.resp
       send (by dt):       do_something_dangerous.resp (contents set earlier by set_response call, so "dangerous thing succeeded")
       exec (by dt):       function_to_call_at_the_end_of_transaction(rollback=False)


Example scenarios where things fail (from ending to beginnig):
 * User does not respond (e.g. because connectivty was lost)
 * Something dangerous take to much time and dt.set_response is not called

If such things happen, then timer kicks in and transaction ends as follows:

DAEMON exec (by dt):       function_to_call_at_the_end_of_transaction(rollback=True)
       send (by dt):       do_something_dangerous.resp: TransactionRolledBackError("Failed to perform something dangeours")


"""
from __future__ import annotations

# Standard imports
import json
import sys

from threading import Timer
from typing import Any, Callable, Optional, Protocol, Union

# Local imports
from mpa.communication.client import Client
from mpa.communication.client import QueryHandlerCallable
from mpa.communication.client import RESPONSE_SUFFIX
from mpa.communication.client import convert_exception_to_message_failure_status
from mpa.communication.common import ConflictingOperationInProgessError
from mpa.communication.common import MissingTransactionStatusError
from mpa.communication.common import TransactionRolledBackError
from mpa.common.logger import Logger

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")


class FinalAction(Protocol):
    def __call__(self, *, rollback: bool) -> None:
        pass


class DaemonTransaction:
    def __init__(self, rollback_error_message: str, client: Client) -> None:
        # self.active is used for primitive GIL based multi-thread safety ---
        # good enough for now, but we may consider real lock in the future
        self.active: bool = False
        self.last_transaction_rolled_back = False
        self.rollback_error_message = rollback_error_message
        self.client = client
        self.topic: Optional[str] = None
        self.final_action: Optional[FinalAction] = None
        self.from_part: Optional[bytes] = None
        self.message_id: Optional[bytes] = None
        self.response: Any = None
        self.timer: Optional[Timer] = None

    def __cleanup(self) -> None:
        self.active = False
        self.topic = None
        self.final_action = None
        self.from_part = None
        self.message_id = None
        self.response = None
        self.timer = None

    def __rollback(self) -> None:
        if not self.active:
            return
        try:
            assert self.final_action is not None
            self.last_transaction_rolled_back = True
            self.final_action(rollback=True)
            assert self.from_part is not None
            assert self.message_id is not None
            error = TransactionRolledBackError(self.rollback_error_message)
            self.response = convert_exception_to_message_failure_status(error)
            self.client.respond(f"{self.topic}{RESPONSE_SUFFIX}", self.response, self.from_part, self.message_id)
        except Exception as exc:  # pylint: disable=broad-except
            logger.exception(exc)
        self.__cleanup()

    def __rollbacker(self) -> Callable[[], None]:
        def call_rollback() -> None:
            self.__rollback()
        return call_rollback

    def __affirm_response_handler(self) -> QueryHandlerCallable:
        def affirm_response_handler(message: Union[str, bytes]) -> Optional[bool]:
            return self.__handle_affirm_response(message)
        return affirm_response_handler

    def __handle_affirm_response(self, message: Union[str, bytes]) -> Optional[bool]:
        if isinstance(message, str):
            logger.warning("Affirm response probably lost --- will not wait for it")
            # Something wrong with communication, let's just proceed with
            # rollback on timeout...
            return False
        if not self.active:
            # TODO do we want to keep from_part and message_id in this function
            # and respond even if transaction was finished earlier???
            # self.client.respond(f"{self.topic}{RESPONSE_SUFFIX}",
            #                     f"{RESPONSE_FAILURE} Transaction was already finished when affirm response was received",
            #                     from_part, message_id)
            logger.warning("Received affirm response in inactive transaction")
            return None
        try:
            affirmed: bool = json.loads(message)
            assert self.from_part is not None
            assert self.message_id is not None
            assert self.timer is not None
            assert self.final_action is not None
            self.timer.cancel()
            if affirmed:
                self.client.respond(f"{self.topic}{RESPONSE_SUFFIX}", self.response, self.from_part, self.message_id)
                self.final_action(rollback=False)
                self.__cleanup()
            else:
                self.__rollback()
        except Exception as exc:  # pylint: disable=broad-except
            logger.exception(exc)
        return None

    def start(self,
              topic: str,
              final_action: FinalAction,
              from_part: bytes,
              message_id: bytes) -> None:
        if self.active:
            raise ConflictingOperationInProgessError(f"Another transaction is already started for {self.topic}. "
                                                     "Execute explicit commit request to accept current state of device.")
        self.active = True
        self.last_transaction_rolled_back = False
        self.topic = topic
        self.final_action = final_action
        self.from_part = from_part
        self.message_id = message_id
        error = MissingTransactionStatusError(f"Handler for {topic} finished unexpectedly")
        self.response = convert_exception_to_message_failure_status(error)
        self.timer = Timer(30.0, self.__rollbacker())
        self.timer.start()

    def set_final_action(self, final_action: FinalAction) -> None:
        if not self.active:
            raise RuntimeError("Impossible to set rollback action for inactive transaction")
        self.final_action = final_action

    def set_response(self, response: Any, *, question: Optional[str] = None) -> None:
        if not self.active:
            raise RuntimeError("Unable to set response in inactive transaction")
        self.client.query(f"affirm.{self.topic}", question, handler=self.__affirm_response_handler())
        self.response = response

    def commit(self) -> bool:
        if not self.active:
            return False
        timer = self.timer
        if self.final_action is not None:
            self.final_action(rollback=False)
        self.__cleanup()
        if timer is not None:
            timer.cancel()
        return True
