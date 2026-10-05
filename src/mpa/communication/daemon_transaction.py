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
       exec (by dt):       function_to_call_at_the_end_of_transaction(rollback=False)
       send (by dt):       do_something_dangerous.resp (contents set earlier by set_response call, so "dangerous thing succeeded")


Example scenarios where things fail (from ending to beginnig):
 * User does not respond (e.g. because connectivty was lost)
 * Something dangerous take to much time and dt.set_response is not called

If such things happen, then timer kicks in and transaction ends as follows:

DAEMON exec (by dt):       function_to_call_at_the_end_of_transaction(rollback=True)
       send (by dt):       do_something_dangerous.resp: TransactionRolledBackError("Failed to perform something dangeours")


"""
from __future__ import annotations

# Standard imports
import enum
import json
import sys

from threading import Lock, Thread, Timer
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
    class State(enum.Enum):
        IDLE = enum.auto()
        ACTIVE = enum.auto()
        CLOSING = enum.auto()

    def __init__(self, rollback_error_message: str, client: Client) -> None:
        self.state: DaemonTransaction.State = DaemonTransaction.State.IDLE
        self.state_change_lock = Lock()
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
        with self.state_change_lock:
            self.topic = None
            self.final_action = None
            self.from_part = None
            self.message_id = None
            self.response = None
            self.timer = None
            self.state = DaemonTransaction.State.IDLE

    def __start_closing(self) -> bool:
        with self.state_change_lock:
            if self.state == DaemonTransaction.State.ACTIVE:
                self.state = DaemonTransaction.State.CLOSING
                if self.timer is not None:
                    self.timer.cancel()
                return True
            return False

    def __close(self, *, rollback: bool) -> None:
        try:
            assert self.state is DaemonTransaction.State.CLOSING
            assert self.final_action is not None
            assert self.from_part is not None
            assert self.message_id is not None
            if rollback:
                self.last_transaction_rolled_back = True
            try:
                self.final_action(rollback=rollback)
                if rollback:
                    error = TransactionRolledBackError(self.rollback_error_message)
                    self.response = convert_exception_to_message_failure_status(error)
            except Exception as exc:  # pylint: disable=broad-except
                logger.exception(exc)
                self.response = convert_exception_to_message_failure_status(exc)
            self.client.respond(f"{self.topic}{RESPONSE_SUFFIX}", self.response, self.from_part, self.message_id)
        except Exception as exc:  # pylint: disable=broad-except
            # __close is called in normal thread (not KillerThread) by timer via __rollbacker and by affirm handler,
            # so we just log and eat all unexpected exceptions (hoping __cleanup below will never throw :)
            logger.exception(exc)
        finally:
            self.__cleanup()

    def __rollback(self) -> None:
        if self.__start_closing():
            self.__close(rollback=True)

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
            # Something wrong with communication --- let the timeout do the rollback...
            return False
        try:
            affirmed: bool = json.loads(message)
        except Exception as exc:  # pylint: disable=broad-except
            # Unparsable message, same as above with wrong communication --- let the timeout do the rollback
            logger.exception(exc)
            return None
        if not affirmed:
            Thread(target=self.__rollback).start()  # potentially long rollback cannot be done directly in handler
        elif self.__start_closing():
            self.__close(rollback=False)
        else:
            # TODO do we want to keep from_part and message_id in this function
            # and respond even if transaction was finished earlier???
            # self.client.respond(f"{self.topic}{RESPONSE_SUFFIX}",
            #                     f"{RESPONSE_FAILURE} Transaction was already finished when affirm response was received",
            #                     from_part, message_id)
            logger.warning("Received affirm response in inactive transaction")
        return None

    def start(self,
              topic: str,
              final_action: FinalAction,
              from_part: bytes,
              message_id: bytes) -> None:
        with self.state_change_lock:
            if self.state is not DaemonTransaction.State.IDLE:
                raise ConflictingOperationInProgessError(f"Another transaction is already started for {self.topic}. "
                                                         "Execute explicit commit request to accept current state of device.")
            self.state = DaemonTransaction.State.ACTIVE
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
        with self.state_change_lock:
            if self.state is DaemonTransaction.State.ACTIVE:
                self.final_action = final_action
                return
        raise RuntimeError("Impossible to set rollback action for inactive transaction")

    def set_response(self, response: Any, *, question: Optional[str] = None) -> None:
        with self.state_change_lock:
            if self.state is DaemonTransaction.State.ACTIVE:
                self.response = response
            else:
                raise RuntimeError("Unable to set response in inactive transaction")
        self.client.query(f"affirm.{self.topic}", question, handler=self.__affirm_response_handler())

    def commit(self) -> bool:
        if not self.__start_closing():
            return False
        try:
            if self.final_action is not None:
                self.final_action(rollback=False)
        finally:
            self.__cleanup()
        return True
