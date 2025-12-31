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
Provides access to arrakis control plane message bus.
"""
from __future__ import annotations

# Standard imports
import base64
import grp
import itertools
import json
import math
import os
import sys
import time
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    Literal,
    Mapping,
    NewType,
    Optional,
    Protocol,
    Sequence,
    Set,
    Tuple,
    TypeVar,
    Union,
    cast,
)

# Third party imports
import zmq

# Local imports
from mpa.common.common import RESPONSE_FAILURE, RESPONSE_OK
from mpa.common.logger import Logger
from mpa.common.killer_thread import KillerThread
from mpa.config.common import CONFIG_DIR_ROOT

DAEMON_DETAILS = "Additional debug info: "
AFFIRM_PREFIX = "affirm"
QUERY_SUFFIX = ".req"
RESPONSE_SUFFIX = ".resp"
SUBSCRIPTION_MARK = '+'
UNSUBSCRIPTION_MARK = '-'
HANDLE_MARK = '@'
UNHANDLE_MARK = '!'
OBSERVER_MARKS = (SUBSCRIPTION_MARK, UNSUBSCRIPTION_MARK)
RESPONDER_MARKS = (HANDLE_MARK, UNHANDLE_MARK)
ADDITION_MARKS = (SUBSCRIPTION_MARK, HANDLE_MARK)
REMOVAL_MARKS = (UNSUBSCRIPTION_MARK, UNHANDLE_MARK)
ALL_MARKS = (SUBSCRIPTION_MARK, UNSUBSCRIPTION_MARK, HANDLE_MARK, UNHANDLE_MARK)
EXISTS_RESULT_NONE = 'N'
EXISTS_RESULT_OBSERVERS_ONLY = 'S'
EXISTS_RESULT_RESPONDERS = 'H'  # There may be pure observers next to responders but we cannot know for sure
POSITIVE_EXISTS_RESULTS = (EXISTS_RESULT_OBSERVERS_ONLY, EXISTS_RESULT_RESPONDERS)
ALL_EXISTS_RESULTS = (EXISTS_RESULT_NONE, EXISTS_RESULT_OBSERVERS_ONLY, EXISTS_RESULT_RESPONDERS)

WAIT_AND_RECEIVE_SINGLE_THREAD_WARNING = '''
Handlers are called within Client.wait_and_receive() which is single thread
function therfore no other incoming messages will be precessed while handler is
running, hence handler shall not run for extended periods of time.'''


# Generic type-name used for typing hints (similar to T in C++ template <typename T>)
# pylint seems to not understand this conventional name despite it being used even in
# python documentation examples...
T = TypeVar('T')  # pylint: disable=invalid-name

logger = Logger(__name__)


def _log_pub_sub_message(prefix: str, topic: Union[bytes, str], from_part: Optional[bytes],
                         message_id: Optional[bytes], message: Optional[bytes]) -> None:
    logger.debug(f"{prefix} [{topic!r}, {from_part!r}, {message_id!r}, {message if message is None else message[:8]!r}]")


# TODO do we want to specify argparse instead of any?
def add_command_line_params(parser: Any) -> None:
    parser.add_argument('--push', dest='client_push', type=str, required=False, default=None,
                        help='PUSH zmq socket (will default to ipc:///dir/group.push if not given, see --dir and --group)')
    parser.add_argument('--sub', dest='client_sub', type=str, required=False, default=None,
                        help='SUB zmq socket (will default to ipc:///dir/group.sub if not given, see --dir and --group)')
    parser.add_argument('--req', dest='client_req', type=str, required=False, default=None,
                        help='REQ zmq socket (will default ot ipc:///dir/group.req if not given, see --dir and --group)')
    parser.add_argument('--group', dest='client_group', type=str, required=False, default=None,
                        help='Group which shall be used for ipc sockets (primary user group will be used if not given)')
    parser.add_argument('--dir', dest='client_dir', type=str, required=False, default=None,
                        help=('Directory in which ipc sockets are present (defaults to /run/mgmtd; '
                              'Note: sockets specified with --push, --sub or --req are not affected by this value; '))
    parser.add_argument('--public_id', dest='client_public_id', type=str, required=False, default=None,
                        help='Preferred public id of client')


def convert_exception_to_message_failure_status(exc: Exception) -> str:
    return f"{RESPONSE_FAILURE} {repr(exc)}\n{DAEMON_DETAILS}PID {os.getpid()}; Timestamp {time.time()}"


def guarded(function: Callable[..., Any]) -> Callable[..., Any]:
    '''
    Converts exceptions to return string (so they will be reported over ZMQ).
    See also example snippet in documentation of sync().
    '''
    def with_guard(*args: Any, **kwargs: Any) -> Any:
        try:
            retval = function(*args, **kwargs)
            if retval is None:
                return RESPONSE_OK
            return retval
        except Exception as exc:  # pylint: disable=broad-except
            logger.exception(exc)
            return convert_exception_to_message_failure_status(exc)
    return with_guard


def sync(function: SyncHandlerCallable) -> RespondingHandlerCallable:
    '''
    Converts SyncHandlerCallable to RespondingHandlerCallable and visually shows in code
    that handler is sync one. Consider following snippet:

    messages = {}
    messages['topic1'] = guarded(sync(do_foo))
    messages['topic2'] = guarded(do_bar)
    messages['topic3'] = do_baz
    client.register_responders(messages)

    It is clear to the reader tath do_foo is sync, and do_bar not, morover it is clear
    that do_baz needs a thorough check for exception safety, as it is not guarded...
    '''
    def with_async_params_ignored(message: bytes,
                                  from_part: bytes,           # pylint: disable=unused-argument
                                  message_id: bytes) -> Any:  # pylint: disable=unused-argument
        return function(message)
    return with_async_params_ignored


def background(function: SyncHandlerCallable, respond: Callable[[Any, bytes, bytes], None], *,
               post_respond: Optional[Callable[[Any], None]] = None) -> RespondingHandlerCallable:
    '''
    Converts SyncHandlerCallable to RespondingHandlerCallable which runs in
    background thread. After thread finishes it sends back its return value or
    exception using respond callable (which takes as arguments message to be
    sent back, public id of requestor and query id. Use respond_to function to
    bind your client and response topic into callable which can be given
    as respond argument. Use post_respond if you want to perform additional
    action after (any/positive/negative) response has been sent --- post_respond
    will have access to response, so it can perform differnt things depending on
    the response type.'''

    def background_part(message: bytes, from_part: bytes, message_id: bytes) -> None:
        retval = function(message)
        respond(retval, from_part, message_id)
        if post_respond is not None:
            try:
                post_respond(retval)
            except Exception as exc:
                logger.error("Post respond raised exception for retval: {retval}")
                logger.exception(exc)

    def foreground_part(message: bytes,
                        from_part: bytes,
                        message_id: bytes) -> Any:
        background = KillerThread(target=background_part, args=(message, from_part, message_id))
        background.start()
        return Async()
    return foreground_part


def respond_to(client: Client, topic: str, *, response_suffix: str = RESPONSE_SUFFIX) -> Callable[[Any, bytes, bytes], None]:
    '''
    Returns callable which binds client instance and response topic and can
    used as argument of background adapter
    '''
    def respond(response_message: Any, asker_id: bytes, query_message_id: bytes) -> None:
        client.respond(f"{topic}{response_suffix}", response_message, asker_id, query_message_id)
    return respond


class PermissionDeniedError(RuntimeError):
    "Raised by default handler of messages not allowed in given Client object"


def generate_not_allowed(group: str) -> RespondingHandlerCallable:
    def not_allowed(message: bytes) -> None:
        raise PermissionDeniedError(f"In group {group} this action is not allowed. "
                                    "If your user belongs to more than one group you may use --group option to "
                                    "select another of your groups")
    return guarded(sync(not_allowed))


class Async:
    """ Used as return value by handlers which want to create response ansychronously."""


class Client:
    '''
    Encapsulates ZMQ communication with other clients through forwarder. See forwarder
    documentation for details on the protocol. To summarize --- forwarder provides
    reliable pub/sub bus where each client can send and listen to annoucements. Eeach
    client needs to connect to forwarder and ping at regular itervals to ensure it has not
    hanged.

    In addition to pure annoucements forwarder adds support for requests and responses ---
    clients may advertise that they will respond to requests on specific topics and
    forwarder will track requets to such advertised topics, so even in case of some client
    hanging the requestor will get notified about his request being handled by such
    defunct party.

    Client provides support for those functions of forwarder. Most commonly used methods
    are:
    send() --- sends announcement
    query() --- sends query
    respond() --- sends response to previously received query from other client
    register_responders() --- adds handlers for queries of other clients
    wait_and_receive() --- blocking call which will receive annoucmenets and queries from
        other clients and call registered handlers

    There are also lower level or more detailed methods --- see their implementation or
    documentations for details.
    '''

    class ConnectionResetError(Exception):
        """
        Connection may be reset if
        a) Client is unsued for long time
        b) Forwarder was restarted while Client was alive
        c) There is some bug somwhere
        This exception may escape Client in cases b) or c).
        """

    class ConnectionInitError(Exception):
        """Raised when forwarder is not responding to hello message."""

    class QueryId:
        def __init__(self, pub_id: bytes, sequence: int):
            self.pub_id = pub_id
            self.sequence = sequence
            self.query_id = "Q".encode() + self.sequence.to_bytes(3, Client.sequence_byte_order)
            self.expected_response_id = "R".encode() + self.pub_id + self.query_id

        def __str__(self) -> str:
            return json.dumps({"QueryId": {"pub_id": f"{self.pub_id!r}", "sequence": f"{self.sequence!r}"}})

        def loosely_matches_response(self, response_id: bytes) -> bool:
            if response_id.startswith(b"R"):
                if response_id == "R".encode() + self.pub_id + "q".encode() + self.query_id[1:]:
                    return True
            elif response_id.startswith(b"r"):
                if response_id[1:] == self.expected_response_id[1:]:
                    return True
                if response_id == "r".encode() + self.pub_id + "q".encode() + self.query_id[1:]:
                    return True
            return False

    class LostRequest:
        def __init__(self, sequence: int, query_topic: Optional[str] = None, response_topic: Optional[str] = None):
            self.sequence = sequence
            self.query_topic = query_topic
            self.response_topic = response_topic

    class LostRequestList(Exception):
        def __init__(self, lost_requests: Sequence[Client.LostRequest]):
            super().__init__()
            self.lost_requests = tuple(lost_requests)

        def __str__(self) -> str:
            retval = ""
            for lost in self.lost_requests:
                retval += f"[{lost.query_topic}|{lost.response_topic}|{lost.sequence}]"
            return retval

    class TimeoutError(RuntimeError):
        pass

    class ExcessivePartsError(RuntimeError):
        pass

    class Timeout:
        def __init__(self, message: str, timeout_ms: Optional[int] = None):
            self.message = f"Timeout when waiting for {message}"
            self.start_time = time.monotonic()
            self.timeout_ms = timeout_ms
            self.time_left_ms = timeout_ms

        def get_time_left_ms(self) -> int:
            if self.timeout_ms is None:
                return sys.maxsize
            self.check_timeout()
            assert self.time_left_ms is not None
            return self.time_left_ms

        def check_timeout(self) -> None:
            used_ms = int(1000 * (time.monotonic() - self.start_time))
            assert self.timeout_ms is not None
            if used_ms > self.timeout_ms:
                raise Client.TimeoutError(self.message)
            self.time_left_ms = self.timeout_ms - used_ms

    class Socket:
        """
        Simple wrapper over zmq socket.
        """

        def __init__(self, context: zmq.Context, uri: str, socket_type: Any):  # type: ignore
            self.sock = context.socket(socket_type)
            self.uri = uri
            self.sock.connect(self.uri)

        # TODO Again strange thing about pyzmq --- I have not found a way to set
        # timeout on receiving multipart message, therefore this method...
        def recv(self, timeout_ms: int) -> Optional[bytes]:
            # evts = self.poller.poll(self.timeout_ms)
            evts = self.sock.poll(timeout_ms)
            if not evts:
                return None
            return cast(bytes, self.sock.recv())

        def more(self) -> bool:
            # for RCVMORE zmq returns int convertible to bool directly
            return bool(self.sock.getsockopt(zmq.RCVMORE))  # pylint: disable=no-member

        def __eat_excessive_parts(self, what: str, timeout_ms: int, raise_error_after_timeout: bool) -> bool:
            """
            Tries to eat excessive parts until timeout.
            Returns True if after timeout there are more excessive parts, False otherwise.
            """
            timeout = Client.Timeout("excessive parts", timeout_ms)
            while self.more():
                part: Optional[bytes]
                try:
                    part = self.recv(timeout.get_time_left_ms())
                except Client.TimeoutError:
                    part = None
                if part is None:
                    message = f"Timeout while waiting for excessive part of {what}."
                    logger.warning(message)
                    if raise_error_after_timeout:
                        raise Client.TimeoutError(message)
                    return True
                logger.error(f"Received excessive part in {what}: {part!r}")
            return False

        def excessive_parts_waiting(self,
                                    what: str,
                                    timeout_ms: int = 0,
                                    *,
                                    raise_error_if_found: bool = False,
                                    raise_error_after_timeout: bool = False) -> bool:
            """
            Returns False if there are no excessive parts waiting before timeout happens.
            Will discrad any new excessive parts until timeout.
            Returns True if there are still any excessive parts after timeout happend.
            If raise_error_after_timeout is True throw Client.TimeoutError instead of returning after timeout.
            If raise_error_if_found is True throw Client.ExcessivePartsError instead of returning True.
            """
            def raise_or_return(value: bool) -> bool:
                if raise_error_if_found:
                    raise Client.ExcessivePartsError(f"Exccesive parts in {what}")
                return value
            if not self.more():
                return False
            if timeout_ms == 0:
                return raise_or_return(True)
            return raise_or_return(self.__eat_excessive_parts(what, timeout_ms, raise_error_after_timeout))

        def send_multipart(self, message: Sequence[bytes], *,
                           shall_log: bool = True, log_all_parts: bool = False) -> None:
            if shall_log or log_all_parts:
                if log_all_parts or len(message) < 4:
                    logger.debug(f"Socket({self.uri}) -> {message}")
                elif len(message) == 4:
                    _log_pub_sub_message(f"Socket({self.uri}) ->", *message)
                else:
                    logger.debug(f"Socket({self.uri}) <- {message[:3]!r} ...")
            self.sock.send_multipart(message)

    class Sub(Socket):
        def __init__(self, context: zmq.Context, uri: str):  # type: ignore
            super().__init__(context, uri, zmq.SUB)  # pylint: disable=no-member

    class Push(Socket):
        def __init__(self, context: zmq.Context, uri: str):  # type: ignore
            super().__init__(context, uri, zmq.PUSH)  # pylint: disable=no-member
            self.sequence = 0

        def inc_seq(self) -> None:
            self.sequence = self.sequence + 1
            if self.sequence >= (1 << 24):
                self.sequence = 1

    class Req(Socket):
        INVALID_ID = b'\0\0\0\0\0\0\0\0'

        def __init__(self, context: zmq.Context, uri: str, *, public_id: Optional[str] = None):  # type: ignore
            super().__init__(context, uri, zmq.REQ)  # pylint: disable=no-member
            # Without linger unsent message (e.g. because RESP is dead) blocks exit from program indefinitely...
            self.sock.setsockopt(zmq.LINGER, 1000)
            self.ping_period_ms = 1000
            self.last_ping = time.monotonic()
            self.lost_list: List[Client.LostRequest] = list()
            self.priv_id = self.INVALID_ID
            self.pub_id = self.INVALID_ID
            if public_id:
                encoded_id = public_id.encode()
                if len(encoded_id) > 7:
                    raise ValueError("Public id must not be longer than 7 bytes after encoding")
            else:
                pid = os.getpid()
                pid_encoded = f"{pid}".encode()
                if len(pid_encoded) > 7:
                    pid_encoded = format(pid, "X").encode()
                if len(pid_encoded) > 7:
                    pid_bytes = pid.to_bytes((pid.bit_length() + 7) // 8, byteorder='big')
                    if len(pid_bytes) < 5:
                        pid_encoded = b'~' + base64.b85encode(pid_bytes)
                    else:
                        pid_encoded = b'~' * (7 - len(pid_bytes)) + pid_bytes
                if len(pid_encoded) >= 7:
                    encoded_id = pid_encoded[-7:]
                if len(pid_encoded) < 7:
                    encoded_id = Path(sys.argv[0]).name.encode()[:7 - len(pid_encoded)] + pid_encoded

            self.pub_id = encoded_id + ((8 - len(encoded_id)) * b'\0')

        def __recv(self, part: str, query: str, response: Optional[str] = None, *, shall_log: bool = True) -> bytes:
            message = self.recv(self.ping_period_ms)
            if message is None:
                error_message = f"Missing {part} in {response + ' ' if response else ''}response to {query} on {self.uri}"
                logger.error(error_message)
                raise RuntimeError(error_message)
            if shall_log:
                logger.debug((f"Socket({self.uri}) <- {message!r} "
                              f"(part {part} in {response + ' ' if response else ''}response to {query})"))
            return message

        def hello(self) -> None:
            self.last_ping = time.monotonic()
            try:
                if self.pub_id != self.INVALID_ID:
                    if self.priv_id != self.INVALID_ID:
                        self.send_multipart(["HELLO".encode(), self.pub_id, self.priv_id], log_all_parts=True)
                    else:
                        self.send_multipart(["HELLO".encode(), self.pub_id], log_all_parts=True)
                else:
                    self.sock.send_string("HELLO")
                # TODO Seems that I don't get something about pyzmq --- no matter what I try
                # I cannot detect failure to send message, example attempts:
                # tracker = self.sock.send("HELLO".encode(), copy=False, track=True)
                # try:
                #    tracker.wait(self.timeout_ms)
                #    if not tracker.done:
                #        logger.critical(f"Unable to send HELLO message to {self.uri}")
                # except:
                #    logger.critical(f"Unable to send HELLO message to {self.uri}")
                #    raise
                # self.poller.register(self.sock, zmq.POLLIN)
                subject = self.__recv("subject", "HELLO").decode("UTF-8")
            except RuntimeError as exc:
                raise Client.ConnectionInitError(exc)
            # print(subject.decode("UTF-8"))
            if subject != "ID":
                print(len(subject))
                print(len("ID"))
                self.__bad_response(subject, "HELLO")
            self.priv_id = self.__recv("PrivateId", "HELLO", shall_log=False)
            self.pub_id = self.__recv("PublicId", "HELLO", shall_log=False)
            # self.poller.unregister(self.sock)
            logger.debug(f"Socket({self.uri}) <- priv_id:{self.priv_id!r}, pub_id:{self.pub_id!r}")
            self.excessive_parts_waiting("HELLO", self.ping_period_ms, raise_error_after_timeout=True)
            self.ping_if_needed()

        def __handle_unexpected_response(self, subject: str, query: str, *, raise_lost_request_list: bool = False) -> None:
            if subject == RESPONSE_OK:
                return
            if subject == "RESET":
                logger.error(f"Received RESET response to {query}")
                raise Client.ConnectionResetError()
            if subject == "LOST":
                # TODO LOST can happen only as response to PING. It was
                # consolidated here with reset, but maybe we shall consider
                # moving it back to separate function
                logger.warning(f"Received LOST response to {query}")
                while True:
                    query_topic = self.__recv("lost message query topic", query).decode("UTF-8")
                    message_id_bytes = self.__recv("lost message id", query)
                    if len(message_id_bytes) != 4 or message_id_bytes[0] != b'Q'[0]:
                        logger.warning(f"Lost message id invalid {message_id_bytes.hex()}")
                        sequence = 0
                    else:
                        sequence = int.from_bytes(message_id_bytes[1:], Client.sequence_byte_order)
                    response_topic = self.__recv("lost message response topic", query).decode("UTF-8")
                    self.lost_list.append(Client.LostRequest(sequence, query_topic, response_topic))
                    if not self.more():
                        break
                if raise_lost_request_list:
                    self.raise_lost_request_list_if_any()
                return None
            self.__bad_response(subject, query)

        def raise_lost_request_list_if_any(self) -> None:
            if len(self.lost_list) > 0:
                exc = Client.LostRequestList(self.lost_list)
                self.lost_list = list()
                raise exc

        def ping(self, *, raise_lost_request_list: bool = False) -> None:
            temp = self.last_ping
            self.last_ping = time.monotonic()
            self.send_multipart(["PING".encode(), self.priv_id], shall_log=False)
            subject = self.__recv("subject", "PING", shall_log=False).decode("UTF-8")
            if subject != RESPONSE_OK:
                self.last_ping = temp  # This ping was not successful...
                self.__handle_unexpected_response(subject, "PING", raise_lost_request_list=raise_lost_request_list)
            if self.excessive_parts_waiting("PING", self.ping_period_ms):
                raise RuntimeError("Excesive parts in ping")
            if subject != "LOST" and self.__shall_ping():
                raise RuntimeError("New ping is needed before current is finished --- overload or misconfiguration")

        def handle(self, topic: str, response_topic: str) -> None:
            self.send_multipart(["HANDLE".encode(), self.priv_id, topic.encode(), response_topic.encode()], log_all_parts=True)
            subject = self.__recv("subject", "HANDLE").decode("UTF-8")
            if len(subject) != 1 or subject[0] not in ['U', 'A', 'D']:
                self.__handle_unexpected_response(subject, "HANDLE")
            self.excessive_parts_waiting("HANDLE", self.ping_period_ms, raise_error_after_timeout=True)
            self.ping_if_needed()

        def exists(self, topics: Sequence[str]) -> str:
            if len(topics) < 1:
                return ""
            message = ["EXISTS".encode()]
            message += [element.encode() for element in topics]
            self.send_multipart(message)
            response = self.__recv("statuses", "EXISTS").decode("UTF-8")
            if len(response) != len(topics) or response[0] not in ['S', 'H', 'N']:
                raise RuntimeError(f"Invalid response for EXISTS: {response}")
            return response

        def ping_if_needed(self, *, raise_lost_request_list: bool = False) -> None:
            if self.__shall_ping():
                self.ping(raise_lost_request_list=raise_lost_request_list)

        def __shall_ping(self) -> bool:
            return self.__time_since_last_ping_ms() > (0.95 * self.ping_period_ms)

        def __time_since_last_ping_ms(self) -> float:
            return 1000 * (time.monotonic() - self.last_ping)

        def time_to_next_ping_ms(self) -> float:
            return self.ping_period_ms - self.__time_since_last_ping_ms()

        def __bad_response(self, subject: str, trigger: str) -> None:
            if subject == "INVALID":
                reason = self.__recv("reason", trigger, "INVALID").decode("UTF-8")
                message = f"Received INVALID response to {trigger} on {self.uri} with reason: " + reason
            else:
                message = f'Unexpected response "{subject}" for {trigger} message on {self.uri}'
            logger.error(message)
            raise RuntimeError(message)

    class TopicWatcher:
        # TopicWatcher interested with only_responders shall react to
        # UNSUBSCRIPTION_MARK, because if nobody listens there cannot be any
        # responders. OTOH SUBSCRIPTION_MARK is not interesting to
        # only_responders TopicWatcher, because the fact that somebody
        # subscribed does not mean he will respond.
        RESPONDER_ONLY_MARKS = RESPONDER_MARKS + (UNSUBSCRIPTION_MARK,)
        # TopicWatcher interested with both listeners and responders shall react
        # to any subscription mark and only to UNSUBSCRIPTION_MARK, because
        # UNHANDLE_MARK does not mean that we lost listeneres
        ANY_TYPE_MARKS = ADDITION_MARKS + (UNSUBSCRIPTION_MARK,)
        RESPONDER_ONLY_POSITIVE_EXISTS_RESULTS = (EXISTS_RESULT_RESPONDERS,)

        def __init__(self,
                     topic: str,
                     handler: TopicWatcherCallable,
                     only_responders: Optional[bool]):
            if len(topic) < 1:
                raise RuntimeError("Empty topic watching is not supported")
            self.topic = topic
            self.handler = handler
            if only_responders:
                self.marks: Sequence[str] = Client.TopicWatcher.RESPONDER_ONLY_MARKS
                self.positive_exists_results: Sequence[str] = Client.TopicWatcher.RESPONDER_ONLY_POSITIVE_EXISTS_RESULTS
            else:
                self.marks = Client.TopicWatcher.ANY_TYPE_MARKS
                self.positive_exists_results = POSITIVE_EXISTS_RESULTS
            self.subscription_result_seen = False
            self.active = False

        def __apply_state(self, active: bool) -> None:
            if self.active == active:
                return
            self.active = active
            self.handler(active)

        def subscription_event_handler(self, subscribed_topic: str, response_topic: Optional[str] = None) -> None:
            #  We do not check if we deal with observer or responder marks for
            #  now, because we only register to those which are changing our state
            self.subscription_result_seen = True
            if subscribed_topic[0] in ADDITION_MARKS:
                self.__apply_state(True)
            elif subscribed_topic[0] in REMOVAL_MARKS:
                self.__apply_state(False)

        def add_exists_result(self, exists_result: str) -> None:
            if self.subscription_result_seen:
                return
            if exists_result in self.positive_exists_results:
                self.__apply_state(True)
                return
            self.__apply_state(False)

    class QueryHandler:
        """
        Class storing query handler and query id, calling handler on responses matching id.

        Handler shall be Callable working in 2 modes:
        a) Normal mode --- argument is bytes containing received message, return shall be None
        b) Missing message mode --- argument is str containig explanation why message is missing, return shall be bool, set to
           True if handler whishes to wait for response anyway, False if handler shall be removed.
        """

        class HandlerCallable(Protocol):
            '''
            Handler which receives response to previously sent query.
            In case forwarder indicates there will likely be no response, the message
            from forwarder is provided to the handler, in such case handler
            needs to decide if it will wait for real response anyway or if it
            wants to be removed from Client.

            Arguments:
            message --- bytes if this is normal response from another client
                        str if forwarder is reporting that normal response is
                        unlikely to be received (e.g. the client which
                        advertised it will respond to our query was disconnected
                        from forwarder)

            Return value:
            None ---  if message was bytes (i.e. normal response)
            False --- if message was str and  handler shall be removed from Client
            True ---  if message was str and handler whishes to wait for normal
                      response anyway --- using True is not reccomended unless
                      there is good reason for it (e.g. as workaround for
                      another client which is known disconnect from forwarder
                      temporarily but it responds anyway after reconnection)

            See also communication.clients.WAIT_AND_RECEIVE_SINGLE_THREAD_WARNING
            '''

            def __call__(self, message: Union[bytes, str]) -> Optional[bool]:
                pass

        def __init__(self, handler: HandlerCallable):
            self.query_id: Optional[Client.QueryId] = None
            self.handler = handler

        def add_id(self, query_id: Client.QueryId) -> None:
            self.query_id = query_id

        def handle_missing_response_indication(self, reason: str) -> bool:
            missing_response_indication = "Forwarder indicated that we will not receive response because"
            response = self.handler(f"{RESPONSE_FAILURE} {missing_response_indication}: {reason}")
            if isinstance(response, bool):
                return response
            raise RuntimeError("Expected bool (True if handler shall wait for response despite missing response indication)")

        def handle(self, message: bytes, from_part: bytes, message_id: bytes) -> bool:
            """ Returns True if QueryHandler handled the message and can be destroyed."""
            if not self.query_id:
                raise RuntimeError("query_id unset at the time handle is called")
            if self.query_id.expected_response_id == message_id:
                logger.debug(f"Received matching response from {from_part!r}")
            elif self.query_id.loosely_matches_response(message_id):
                logger.warning(f"Received loosely matching response from {from_part!r}: {message_id!r}")
            else:
                logger.info(f"Ignoring not matching response from {from_part!r}: {message_id!r}")
                return False
            try:
                response = self.handler(message)
                if response is not None:
                    raise RuntimeError(f"Query handler shall not return anything, but it did: {response}")
            except Exception as exc:  # pylint: disable=broad-except
                logger.exception(exc)
            return True

    class Handlers:
        '''
        Storage for handler functions. Instance attributes (except response_topics) are
        maps from topics to handlers. See docs of specific handler types for their
        intended use.

        Non-responding handlers --- in general we can have multiple non-responding handlers
        for given topic, even of different types:
            subscription  --- watching new (un)subscriptions of other clients (see
                              SubscriptionWatcherCallable)
            topic_watcher --- indirect special handlers which provide SubscriptionWatcherCallable
                              stored in subscription, but doing an initial check for preexisiting
                              subscriptions
            query         --- created by Client.query() method
            observer      --- receive messages with headers sent to given topic (see
                              ObservingHandlerCallable) as such they could in theory
                              create a response, but they are not meant for that purpose
            trivial       --- receive messages without headers set to given topic (see
                              TrivialHandlerCallable)

        Responding handlers --- in general for any topic we currently allow only one
        responding handler --- e.g. you cannot have both responding and hidden_responding
        for same topic. We keep them them in separate attributes to simplify type
        checking, but we have commond attribute response_topics for all types of
        responding handlers):
            affirm            --- special short lived handlers for queries which may require
                                  additional affirmation (see Client.query() and
                                  AffirmHandlerCallable)
            responding        --- normal responding handlers intended for the life of the client
                                  we are advertising to other clients their existence via HANDLE
                                  message to forwarder
            hidden_responding --- similar to responding but client is not advertising their
                                  existance --- intendent for cases where we want to nicely send
                                  failure responses to clients sending queries blindly without
                                  checking if there are handlers advertised
        '''

        # We don't see benefit in refactoring of Handlers to limit instance attributes yet:
        # pylint: disable=too-many-instance-attributes
        def __init__(self) -> None:

            # Non responding handlers
            self.subscription: Dict[str, Set[SubscriptionWatcherCallable]] = dict()
            self.topic_watcher: Dict[str, Set[Client.TopicWatcher]] = dict()
            self.query: Dict[str, Set[Client.QueryHandler]] = dict()
            self.observer: Dict[str, Set[ObservingHandlerCallable]] = dict()
            self.trivial: Dict[str, Set[TrivialHandlerCallable]] = dict()

            # Responding handlers
            self.affirm: Dict[str, AffirmHandlerCallable] = dict()
            self.responding: Dict[str, RespondingHandlerCallable] = dict()
            self.hidden_responding: Dict[str, RespondingHandlerCallable] = dict()

            # Helper for responding handlers
            self.response_topics: Dict[str, str] = dict()

        def subscriptions(self) -> Iterator[str]:
            return itertools.chain(self.responding.keys(),
                                   self.hidden_responding.keys(),
                                   self.trivial.keys(),
                                   self.observer.keys(),
                                   self.query.keys())

        def remove_stale_query_handlers(self) -> None:
            for topic, qhset in self.query.items():
                persisting = {hnd for hnd in qhset if hnd.handle_missing_response_indication("Forwarder connection reset")}
                self.query[topic] = persisting
            self.query = {topic: qhset for topic, qhset in self.query.items() if len(qhset) > 0}

        def __is_topic_registered(self, topic: str) -> bool:
            for dic in (self.observer, self.responding, self.hidden_responding,
                        self.trivial, self.query, self.subscription, self.affirm):
                if topic in cast(Dict[str, Any], dic):
                    return True
            return False

        def __add_handler(self, topic: str, handler: T, dictionary: Dict[str, Set[T]]) -> bool:
            """ Returns True if this is new topic which needs to be subscribed. """
            is_new = not self.__is_topic_registered(topic)
            if topic not in dictionary:
                dictionary[topic] = set()
                dictionary[topic].add(handler)
            else:
                topic_set = dictionary[topic]
                if handler in topic_set:
                    raise KeyError(f"Handler already added for topic {topic}")
                dictionary[topic].add(handler)
            return is_new

        def __remove_handler(self, topic: str, handler: T, dictionary: Dict[str, Set[T]]) -> bool:
            """ Returns True if this topic is no longer in use and needs to be unsubscribed. """
            if topic not in dictionary:
                raise KeyError(f"No handlers for topic {topic}")
            dictionary[topic].remove(handler)
            if len(dictionary[topic]) == 0:
                dictionary.pop(topic)
                return not self.__is_topic_registered(topic)
            return False

        @staticmethod
        def __get_subscription_topics(topic: str,
                                      marks: Optional[Sequence[str]] = None) -> Sequence[str]:
            if len(topic) == 0 or topic[0] not in ALL_MARKS:
                if marks is None:
                    marks = ALL_MARKS
                topics = [f"{prefix}{topic}" for prefix in marks]
            else:
                topics = [topic]
            return topics

        def add_query_handler(self,
                              topic: str,
                              handler: Client.QueryHandler.HandlerCallable) -> Tuple[bool, Client.QueryHandler]:
            query_handler = Client.QueryHandler(handler)
            is_new_topic = self.__add_handler(topic, query_handler, self.query)
            return is_new_topic, query_handler

        def add_subscription_watcher(self,
                                     topic: str,
                                     handler: SubscriptionWatcherCallable) -> Sequence[str]:
            topics = self.__get_subscription_topics(topic)
            new_topics = []
            for top in topics:
                if self.__add_handler(top, handler, self.subscription):
                    new_topics.append(top)
            return new_topics

        def remove_subscription_watcher(self,
                                        topic: str,
                                        handler: SubscriptionWatcherCallable) -> Sequence[str]:
            topics = self.__get_subscription_topics(topic)
            removed_topics = []
            for top in topics:
                if self.__remove_handler(top, handler, self.subscription):
                    removed_topics.append(top)
            return removed_topics

        def add_topic_watcher(self, watcher: Client.TopicWatcher) -> Sequence[str]:
            # Ensure this is new handler
            if watcher.topic not in self.topic_watcher:
                self.topic_watcher[watcher.topic] = set()
            topic_set = self.topic_watcher[watcher.topic]
            for old_watcher in topic_set:
                if old_watcher.handler == watcher.handler:
                    raise KeyError(f"This topic watcher is already added for {watcher.topic}")
            topic_set.add(watcher)

            # Add subscription handlers
            topics = self.__get_subscription_topics(watcher.topic, watcher.marks)
            new_topics: List[str] = []
            for top in topics:
                new_topics += self.add_subscription_watcher(top, watcher.subscription_event_handler)
            return new_topics

        def remove_topic_watcher(self, topic: str, handler: TopicWatcherCallable) -> Sequence[str]:
            if topic not in self.topic_watcher:
                raise KeyError(f"No topic watchers for {topic}")
            topic_set = self.topic_watcher[topic]
            for watcher in topic_set:
                if watcher.handler == handler:
                    topic_set.remove(watcher)
                    break
            else:
                raise KeyError(f"No such topic watcher for {topic}")
            if len(topic_set) == 0:
                self.topic_watcher.pop(topic)
            topics = self.__get_subscription_topics(topic, watcher.marks)
            removed_topics: List[str] = []
            for top in topics:
                removed_topics += self.remove_subscription_watcher(top, watcher.subscription_event_handler)
            return removed_topics

        def __add_responding_handler_impl(self, query_topic: str, response_topic: str,
                                          handler: RespondingHandlerCallable,
                                          target: Dict[str, RespondingHandlerCallable],
                                          other: Dict[str, RespondingHandlerCallable]) -> bool:
            is_new = True
            if query_topic in self.affirm:
                raise RuntimeError("Query topic conflicts with registered affirm request topic")
            if query_topic in other:
                raise RuntimeError("No support for switching from hidden responding to normal responding or vice versa")
            if query_topic in target:
                if self.response_topics[query_topic] != response_topic:
                    raise RuntimeError("No support for response topic change in client")
                is_new = False
            target[query_topic] = handler
            self.response_topics[query_topic] = response_topic
            return is_new

        def add_responding_handler(self, query_topic: str, response_topic: str,
                                   handler: RespondingHandlerCallable) -> bool:
            return self.__add_responding_handler_impl(query_topic, response_topic, handler,
                                                      self.responding,
                                                      self.hidden_responding)

        def add_hidden_responding_handler(self, query_topic: str, response_topic: str,
                                          handler: RespondingHandlerCallable) -> bool:
            return self.__add_responding_handler_impl(query_topic, response_topic, handler,
                                                      self.hidden_responding,
                                                      self.responding)

        def add_affirm_request_handler(self, query_topic: str, response_topic: str, handler: AffirmHandlerCallable) -> bool:
            '''
            For now we support only one pending affirmation requiring request per topic and it
            cannot be same as normal responding topic
            '''
            if query_topic in self.affirm:
                raise RuntimeError("Non unique affirm request topic")
            if query_topic in self.responding or query_topic in self.hidden_responding:
                raise RuntimeError("Query topic conflicts with registered responding query topic")
            is_new = not self.__is_topic_registered(query_topic)
            self.affirm[query_topic] = handler
            self.response_topics[query_topic] = response_topic
            return is_new

        def remove_affirm_request_handler(self, query_topic: str) -> bool:
            self.affirm.pop(query_topic)
            self.response_topics.pop(query_topic)
            return not self.__is_topic_registered(query_topic)

        def add_trivial_handler(self, query_topic: str, handler: TrivialHandlerCallable) -> bool:
            return self.__add_handler(query_topic, handler, self.trivial)

        def remove_trivial_handler(self, query_topic: str, handler: TrivialHandlerCallable) -> bool:
            return self.__remove_handler(query_topic, handler, self.trivial)

        def add_observer_handler(self, query_topic: str, handler: ObservingHandlerCallable) -> bool:
            return self.__add_handler(query_topic, handler, self.observer)

        def remove_observer_handler(self, query_topic: str, handler: ObservingHandlerCallable) -> bool:
            return self.__remove_handler(query_topic, handler, self.observer)

        def call_query_handlers(self, topic: str, from_part: bytes, message_id: bytes, message: bytes) -> bool:
            """ Returns true if there are no more handlers (query and other!) for topic and topic needs to be unsubscribed. """
            if topic not in self.query.keys():
                return False

            topic_list = list(self.query[topic])
            handled = {hnd for hnd in topic_list if hnd.handle(message, from_part, message_id)}
            self.query[topic] -= handled
            if len(self.query[topic]) == 0:
                self.query.pop(topic)
                return not self.__is_topic_registered(topic)
            return False

        def inform_query_handlers_about_lost_response(self, lost: Client.LostRequest) -> bool:
            """
            Returns true if lost request indication was processed by one of the handlers.
            """
            if lost.response_topic and len(lost.response_topic) > 0:
                topic = lost.response_topic
                try:
                    topic_set = self.query[topic]
                except KeyError:
                    logger.warning(f"Received lost request indication for unregistered topic {topic}")
                    return False
                if self.__handle_lost_message_in_query_handler(lost.sequence, topic, topic_set):
                    return True
                else:
                    logger.warning("Lost query id not found for response topic")
            else:
                # We need to identify query by id
                for topic, topic_set in self.query.items():
                    if self.__handle_lost_message_in_query_handler(lost.sequence, topic, topic_set,
                                                                   query_topic=lost.query_topic):
                        return True
            return False

        def __handle_lost_message_in_query_handler(self, sequence: int, response_topic: str, topic_set: Set[Client.QueryHandler],
                                                   *, query_topic: Optional[str] = None) -> bool:
            """
            Returns true if lost message indication was processed by one of the handlers.
            """
            for hnd in topic_set:
                if hnd.query_id and hnd.query_id.sequence == sequence:
                    if query_topic is None:
                        message = f"LOST response indication on topic '{response_topic}' received from forwarder"
                    else:
                        message = f"LOST request indication for topic '{query_topic}' received from forwarder"
                    persisting = hnd.handle_missing_response_indication(message)
                    if not persisting:
                        topic_set.remove(hnd)
                    assert len(topic_set) == len(self.query[response_topic])
                    if len(topic_set) > 0:
                        self.query.pop(response_topic)
                    return True
            return False

        def call_normal_handler(self, topic: str,
                                from_part: bytes,
                                message_id: bytes,
                                message: bytes) -> Tuple[Optional[str], Optional[Any]]:
            """
            Calls normal handler.

            Returns response topic and message to be sent back or pair of Nones if there
            is no handler for topic or if handler is async and there is no response yet.
            """
            if topic in self.observer.keys():
                for observer in self.observer[topic]:
                    observer(message, from_part, message_id)
            if topic in self.trivial.keys():
                for trivial in self.trivial[topic]:
                    trivial(message)
            if topic in self.affirm.keys():
                # TODO would be good to connect affirm handler with query
                # handler to ensure removal of affirm handler if query response
                # comes without affirm request... However we don't expect long
                # life of clients which have affirm handlers, so not done yet
                response = self.affirm[topic](self.response_topics[topic], message, from_part, message_id)
            elif topic in self.responding.keys():
                response = self.responding[topic](message, from_part, message_id)
            elif topic in self.hidden_responding.keys():
                response = self.hidden_responding[topic](message, from_part, message_id)
            else:
                return None, None
            if isinstance(response, Async):
                return None, None
            if response is None:
                response = (f"{RESPONSE_FAILURE} missing internal handler response\n"
                            f"{DAEMON_DETAILS}{os.getpid()}")
            return self.response_topics[topic], response

    sequence_byte_order: Literal['big', 'little'] = "big"

    def __init__(self,
                 *,
                 args: Any = None,
                 directory: Union[None, str, os.PathLike[Any]] = None,
                 group: Optional[str] = None,
                 push: Optional[str] = None,
                 sub: Optional[str] = None,
                 req: Optional[str] = None,
                 public_id: Optional[str] = None,
                 allowed_messages: Union[None, str, os.PathLike[Any]] = None,
                 not_allowed_handler: Optional[RespondingHandlerCallable] = None):
        # TODO we shall unify forwarder and client socket config better...

        def return_first_defined(*pos_args: Any) -> Any:
            return next((arg for arg in pos_args if arg is not None), None)

        if args is not None:
            directory = return_first_defined(directory, args.client_dir)
            group = return_first_defined(group, args.client_group)
            push = return_first_defined(push, args.client_push)
            sub = return_first_defined(sub, args.client_sub)
            req = return_first_defined(req, args.client_req)
            public_id = return_first_defined(public_id, args.client_public_id)
        directory = return_first_defined(directory, '/run/mgmtd')
        assert directory is not None
        if group is None:
            grpid = os.getegid()
            group = grp.getgrgid(grpid)[0]
        if None in (req, push, sub):
            if not isinstance(directory, Path):
                directory = Path(directory)
            if directory.exists() is False or directory.is_dir() is False:
                raise self.ConnectionInitError(f"Expected '{directory}' to be existing directory for sockets")
        if allowed_messages is None:
            self.allowed_messages_filename: Path = self.__get_allowed_messages_from_own_name(group)
        elif not_allowed_handler is None:
            raise RuntimeError("Not allowed handler must be provided if allowed messages are not read from group config file")
        else:
            self.allowed_messages_filename = Path(allowed_messages)
        if not_allowed_handler is None:
            self.not_allowed_handler = generate_not_allowed(group)
        else:
            self.not_allowed_handler = not_allowed_handler
        prefix = f"ipc://{os.path.abspath(directory)}/{group + '.' if group else ''}"
        self.context = zmq.Context()
        self.sub = self.Sub(self.context, return_first_defined(sub, prefix + "sub"))
        self.push = self.Push(self.context, return_first_defined(push, prefix + "push"))
        self.req = self.Req(self.context, return_first_defined(req, prefix + "req"), public_id=public_id)
        logger.debug((f"init:Client.__init__ calculated group={group}, "
                      f"push={self.push.uri}, sub={self.sub.uri}, req={self.req.uri}, "
                      f"allowed={self.allowed_messages_filename}"))
        self.handlers = self.Handlers()
        self.req.hello()

    def __get_timeout_ms(self, timeout: Timeout) -> int:
        return min(int(math.ceil(self.req.time_to_next_ping_ms())), timeout.get_time_left_ms())

    @staticmethod
    def __autoconvert(message: Any) -> bytes:
        if not isinstance(message, bool) and not message:
            return "".encode()
        if isinstance(message, (bytes, bytearray)):
            return message
        return json.dumps(message).encode()

    @staticmethod
    def __get_allowed_messages_from_own_name(group: str) -> Path:
        tag, _dash, service = sys.argv[0].rpartition('/')[2].rpartition('-')
        config_dir = CONFIG_DIR_ROOT / tag
        if not config_dir.exists():
            raise RuntimeError(f"Directory {config_dir} does not exist")
        if not config_dir.is_dir():
            raise RuntimeError(f"Path {config_dir} is not directory")
        config_file = config_dir / (service + '@' + group + '.messages.conf')
        if len(tag) == 0 and not config_file.exists():
            logger.warning(f"Unable to decipher tag for config from {sys.argv[0]}, and direct file {config_file} does not exist")
        return config_file

    def __reinit(self) -> None:
        self.req.hello()
        self.handlers.remove_stale_query_handlers()
        for topic in self.handlers.subscriptions():
            self.sub.sock.subscribe(topic)
        for query, response in self.handlers.response_topics.items():
            # TODO add unhandle support
            # we cannot unhandle yet, but we don't expect long life of clients
            # so we advertise affirm handlers anyway, as otherwise we would
            # need to deal with unhandlable requests reports
            # Anyway we can avoid advertising them by adding self.handlers.affirm
            # to the "if" below
            if query not in self.handlers.hidden_responding:
                self.req.handle(query, response)
        self.req.ping_if_needed()

    def __try_ping(self, *, raise_lost_request_list: bool = False) -> None:
        try:
            self.req.ping_if_needed(raise_lost_request_list=raise_lost_request_list)
        except Client.ConnectionResetError:
            self.__reinit()

    def __sub_recv(self, timeout: Client.Timeout, *, raise_lost_request_list: bool = False) -> bytes:
        while True:
            part = self.sub.recv(timeout_ms=self.__get_timeout_ms(timeout))
            if part is not None:
                return part
            self.req.ping_if_needed(raise_lost_request_list=raise_lost_request_list)

    def send(self, topic: str, message: Any = None) -> None:
        """
        Sends message with given topic.

        Parameter message shall be one of:
        a) None --- in such case message body will be empty
        b) bytes --- in such case message body will contain message parameter directly
        c) any other type convertible to str with help of json.dumps --- in such case
           message body will json representation message
        """
        self.__try_ping()
        self.push.inc_seq()
        publish_id = "M".encode() + self.push.sequence.to_bytes(3, Client.sequence_byte_order)
        self.push.send_multipart([topic.encode(), self.req.priv_id, self.req.pub_id, publish_id, self.__autoconvert(message)])

    def respond(self, topic: str, response_message: Any, asker_id: bytes, query_message_id: bytes) -> None:
        self.__try_ping()
        self.push.send_multipart([topic.encode(),
                                  self.req.priv_id,
                                  self.req.pub_id,
                                  "R".encode() + asker_id + query_message_id,
                                  self.__autoconvert(response_message)])

    def exists(self, topics: Sequence[str]) -> str:
        self.__try_ping()
        return self.req.exists(topics)

    def __register_query_handler(self, topic: str,
                                 handler: Client.QueryHandler.HandlerCallable) -> Client.QueryHandler:
        is_new_topic, query_handler = self.handlers.add_query_handler(topic, handler)
        if is_new_topic:
            self.sub.sock.subscribe(topic)
        return query_handler

    def __register_affirm_request_handler(self,
                                          query_topic: str,
                                          response_topic: str,
                                          affirm_prefix: str,
                                          handler: AffirmHandlerCallable) -> None:
        affirm_query_topic = f"{affirm_prefix}.{query_topic}"
        affirm_response_topic = f"{affirm_prefix}.{response_topic}"
        if self.handlers.add_affirm_request_handler(affirm_query_topic, affirm_response_topic, handler):
            self.sub.sock.subscribe(affirm_query_topic)
            # TODO add unhandle support
            # we cannot unhandle yet, but we don't expect long life of clients
            # so advertise affirm handlers anyway, as otherwise we would
            # need to deal with unhandlable requests reports
            self.req.handle(affirm_query_topic, affirm_response_topic)

    def query(self,
              topic: str,
              message: Any = None,
              handler: Optional[QueryHandler.HandlerCallable] = None,
              *,
              affirm_handler_generator: Optional[AffirmHandlerGenerator] = None,
              query_suffix: str = QUERY_SUFFIX,
              response_suffix: str = RESPONSE_SUFFIX,
              affirm_prefix: str = AFFIRM_PREFIX,
              query_topic: Optional[str] = None,
              response_topic: Optional[str] = None) -> Client.QueryId:
        """
        Sends query to which caller expects a response.

        If message parameter is None query message will have empty body (but of course
        topic, sender and query id will be filled). See Client.send() for more details
        about message parameter.

        Query topic will be constructed as concatenation of parameters topic and
        query_suffix. Accordingly expected response topic will be constructed from topic
        and response_suffix.

        For cases where query and response topics do not share common core caller can
        give query_topic or response_topic parameter directly --- in such case topic
        parameter and corrosponding suffix parameter will be ignored.

        If handler parameter is given it will be called automatically on matching
        response and discarded afterwards. See Client.QueryHandler for details about
        requirements for handler.

        Client.QueryId is returned from this function so caller can skip handler parameter
        and instead use handler registered by himself earlier.

        If affirm_handler_generator is not None additional affirm_handler related to this
        query will be created. This affirm handler will be called if we receive affirm
        request matching this query id. TODO this affirm handler shall be removed if we
        receive query response without affirm request (not implemented yet, so do not use
        affirm handlers in long lived daemons until it is implemented).
        """
        self.__try_ping()
        if not query_topic:
            query_topic = f"{topic}{query_suffix}"
        if not response_topic:
            response_topic = f"{topic}{response_suffix}"
        self.push.inc_seq()
        query_id = self.QueryId(self.req.pub_id, self.push.sequence)
        if affirm_handler_generator is not None:
            self.__register_affirm_request_handler(query_topic, response_topic, affirm_prefix, affirm_handler_generator(self))
        if handler:
            query_handler = self.__register_query_handler(response_topic, handler)
            query_handler.add_id(query_id)
        self.push.send_multipart([query_topic.encode(),
                                  self.req.priv_id,
                                  self.req.pub_id,
                                  query_id.query_id,
                                  self.__autoconvert(message)])
        return query_id

    def register_responding_handler(self,
                                    topic: str,
                                    handler: RespondingHandlerCallable,
                                    *,
                                    hidden: bool = False,
                                    query_suffix: str = QUERY_SUFFIX,
                                    response_suffix: str = RESPONSE_SUFFIX,
                                    query_topic: Optional[str] = None,
                                    response_topic: Optional[str] = None) -> None:
        self.__try_ping()
        if not query_topic:
            query_topic = f"{topic}{query_suffix}"
        if not response_topic:
            response_topic = f"{topic}{response_suffix}"
        if hidden:
            if self.handlers.add_hidden_responding_handler(query_topic, response_topic, handler):
                self.sub.sock.subscribe(query_topic)
        elif self.handlers.add_responding_handler(query_topic, response_topic, handler):
            self.sub.sock.subscribe(query_topic)
            self.req.handle(query_topic, response_topic)

    def has_responding_handler(self,
                               topic: str,
                               *,
                               query_suffix: str = QUERY_SUFFIX,
                               query_topic: Optional[str] = None) -> bool:
        if not query_topic:
            query_topic = f"{topic}{query_suffix}"
        return query_topic in self.handlers.responding

    def __subscribe(self, topic: str, handler: T, handlers_action: Callable[[str, T], bool]) -> None:
        if handlers_action(topic,  handler):
            self.sub.sock.subscribe(topic)

    def __unsubscribe(self, topic: str, handler: T, handlers_action: Callable[[str, T], bool]) -> None:
        if handlers_action(topic,  handler):
            self.sub.sock.unsubscribe(topic)

    def register_trivial_handler(self, topic: str, handler: TrivialHandlerCallable) -> None:
        self.__subscribe(topic, handler, self.handlers.add_trivial_handler)

    def unregister_trivial_handler(self, topic: str, handler: TrivialHandlerCallable) -> None:
        self.__unsubscribe(topic, handler, self.handlers.remove_trivial_handler)

    def register_observer_handler(self, topic: str, handler: ObservingHandlerCallable) -> None:
        self.__subscribe(topic, handler, self.handlers.add_observer_handler)

    def unregister_observer_handler(self, topic: str, handler: ObservingHandlerCallable) -> None:
        self.__unsubscribe(topic, handler, self.handlers.remove_observer_handler)

    def register_subscription_watcher(self, topic: str, handler: SubscriptionWatcherCallable) -> None:
        self.__try_ping()
        new_topics = self.handlers.add_subscription_watcher(topic, handler)
        for top in new_topics:
            self.sub.sock.subscribe(top)

    def unregister_subscription_watcher(self, topic: str, handler: SubscriptionWatcherCallable) -> None:
        self.__try_ping()
        removed_topics = self.handlers.remove_subscription_watcher(topic, handler)
        for top in removed_topics:
            self.sub.sock.unsubscribe(top)

    def register_topic_watcher(self,
                               topic: str,
                               handler: TopicWatcherCallable,
                               *,
                               only_responders: Optional[bool] = None) -> None:
        """
            Lets handler know if there are any listeners/responders for given topic.

            Handler will be called with True as soon as there is at least one
            listener or responder for given topic.

            If only_responders is set to True pure listeners will be ignored.
        """
        watcher = Client.TopicWatcher(topic, handler, only_responders)
        new_topics = self.handlers.add_topic_watcher(watcher)
        for top in new_topics:
            self.sub.sock.subscribe(top)
        watcher.add_exists_result(self.req.exists([topic]))

    def unregister_topic_watcher(self,
                                 topic: str,
                                 handler: TopicWatcherCallable) -> None:
        removed_topics = self.handlers.remove_topic_watcher(topic, handler)
        for top in removed_topics:
            self.sub.sock.unsubscribe(top)

    def __receive_subscription_message(self, topic: str, timeout: Client.Timeout) -> Optional[bytes]:
        if topic[0] in OBSERVER_MARKS:
            message = None
        elif topic[0] in RESPONDER_MARKS:
            if self.sub.more():
                message = self.__sub_recv(timeout=timeout)
            else:
                message = None
        return message

    __ReceivedPartsTuple = NewType("__ReceivedPartsTuple",
                                   Tuple[Optional[bytes], Optional[bytes], Optional[bytes], Optional[bytes]])

    def __receive_normal_message(self, timeout: Client.Timeout) -> __ReceivedPartsTuple:
        global_sequence, from_part, message_id, message = None, None, None, None
        if self.sub.more():
            global_sequence = self.__sub_recv(timeout=timeout)
        if self.sub.more():
            from_part = self.__sub_recv(timeout=timeout)
        if self.sub.more():
            message_id = self.__sub_recv(timeout=timeout)
        if self.sub.more():
            message = self.__sub_recv(timeout=timeout)
        return Client.__ReceivedPartsTuple((global_sequence, from_part, message_id, message))

    def wait_and_receive(self, timeout_ms: Optional[int] = None) -> None:
        try:
            self.__try_ping(raise_lost_request_list=True)
            timeout = self.Timeout(f"message on {self.sub.uri}", timeout_ms)
            raw_topic = self.__sub_recv(timeout=timeout, raise_lost_request_list=True)
            topic = raw_topic.decode("utf-8")
            if topic[0] in ALL_MARKS:
                message = self.__receive_subscription_message(topic, timeout)
                if topic in self.handlers.subscription:
                    for hand in self.handlers.subscription[topic]:
                        hand(topic, None if message is None else message.decode("utf-8"))
                        self.req.ping_if_needed()
                return
            global_sequence, from_part, message_id, message = self.__receive_normal_message(timeout)
            if None in [from_part, message_id, message]:
                logger.error((f"Ignoring invalid message: topic={topic}, "
                              f"from={from_part!r}, message_id={message_id!r}, body={message!r}"))
                return
            _log_pub_sub_message(f"Socket({self.sub.uri}) <-", topic, from_part, message_id, message)
            assert from_part is not None
            assert message_id is not None
            assert message is not None
            while self.sub.excessive_parts_waiting("excessive parts eating", self.__get_timeout_ms(timeout)):
                self.req.ping_if_needed()
            if self.handlers.call_query_handlers(topic, from_part, message_id, message):
                self.sub.sock.unsubscribe(topic)
            self.req.ping_if_needed()
            response_topic, response = self.handlers.call_normal_handler(topic, from_part, message_id, message)
            if response_topic is not None:
                self.respond(response_topic, response, from_part, message_id)
            self.req.ping_if_needed()
            self.req.raise_lost_request_list_if_any()
        except Client.LostRequestList as lost_list:
            # TODO we shall be doing this check on all externally available
            # methods which can trigger ping --- check if we can use something
            # like this: https://stackoverflow.com/a/18912081 with still keeping
            # typing hints intact...
            handled = 0
            for lost in lost_list.lost_requests:
                # TODO consider removing from list reports about requests which were eaten by query handlers...
                if self.handlers.inform_query_handlers_about_lost_response(lost):
                    handled += 1
            if len(lost_list.lost_requests) == handled:
                logger.warning(f"Handled all of lost: {lost}")
            else:
                raise

    def register_responders(self, messages: Mapping[str, RespondingHandlerCallable],
                            handler_for_not_allowed: Optional[RespondingHandlerCallable] = None,
                            *,
                            add_handler_for_not_allowed: bool = True) -> None:
        self.__try_ping()
        if self.allowed_messages_filename and self.allowed_messages_filename.is_file():
            if handler_for_not_allowed is None:
                handler_for_not_allowed = self.not_allowed_handler
            with open(self.allowed_messages_filename) as allowed_messages_file:
                allowed_messages = set()
                for line in allowed_messages_file:
                    line = line.strip()
                    if line[0] == '#':
                        continue
                    if line[0] == '?':
                        allowed_messages.add(line[1:].strip())
                        continue
                    if line not in messages:
                        logger.critical(f"Invalid config --- unknown allowed message: '{line}', known messages:{messages.keys()}")
                        sys.exit(1)
                    allowed_messages.add(line)
            for topic in messages:
                if topic in allowed_messages:
                    self.register_responding_handler(topic, messages[topic])
                elif add_handler_for_not_allowed:
                    self.register_responding_handler(topic, handler_for_not_allowed, hidden=True)
        else:
            for topic, handler in messages.items():
                self.register_responding_handler(topic, handler)


class RespondingHandlerCallable(Protocol):
    '''
    Handler which receives message with headers with intention to create
    response. For simple case where response can be created immediately it can
    be returend directly by handler --- see decorator sync() and
    SyncHandlerCallable. If creation of response requires more time handler
    shall return Async(), prepare response in other thread and call
    Client.respond() when ready.
    We require specific naming of arguments in handler as they are of same type.

    See also communication.client.WAIT_AND_RECEIVE_SINGLE_THREAD_WARNING
    '''

    def __call__(self, message: bytes, from_part: bytes, message_id: bytes) -> Any:
        pass


class SyncHandlerCallable(Protocol):
    '''
    Handler which receives message without headers and returns response
    immediatelly --- use sync() decorator to convert it to
    RespondingHandlerCallable().

    See also communication.client.WAIT_AND_RECEIVE_SINGLE_THREAD_WARNING
    '''

    def __call__(self, __message: bytes) -> Any:
        pass


class ObservingHandlerCallable(Protocol):
    '''
    Handler which receives message with headers without intention of responding
    to the message --- you may still call Client.respond() using headers received by
    this handler but such response will be probably not expected by the sender
    of original message.

    We require specific naming of arguments in handler as they are of same type.

    See also communication.client.WAIT_AND_RECEIVE_SINGLE_THREAD_WARNING
    '''

    def __call__(self, message: bytes, from_part: bytes, message_id: bytes) -> None:
        pass


class TrivialHandlerCallable(Protocol):
    '''
    Handler which receives message without headers (~Obviously responding
    is impossible due to that)

    See also communication.client.WAIT_AND_RECEIVE_SINGLE_THREAD_WARNING
    '''

    def __call__(self, __message: bytes) -> None:
        pass


class TopicWatcherCallable(Protocol):
    '''
    Handler which receives True as soon as Client knows that given topic has
    been subscribed by any other client and False as soon as Client knows that
    given topic has been unsubscribed by all other clients. See
    Client.register_topic_watcher() for more detils.

    See also communication.client.WAIT_AND_RECEIVE_SINGLE_THREAD_WARNING
    '''

    def __call__(self, __is_subscribed: bool) -> None:
        pass


class SubscriptionWatcherCallable(Protocol):
    '''
    Handler which receives special (un)subscription messages generated by
    forwarder when other clients start/stop to listen to or advertise they will
    start/stop to respond to some topics.

    See TopicWatcherCallable as it provides higher level abstraction than this
    handler which is more likely to be useful for user of Client.

    Note that first letter of subscribed_topic will be one of {ALL_MARKS} and is
    information about kind of (un)subcription message --- as specified by
    forwarder protocol --- refer to it for details.

    See also communication.client.WAIT_AND_RECEIVE_SINGLE_THREAD_WARNING
    '''

    def __call__(self, subscribed_topic: str, response_topic: Optional[str] = None) -> None:
        pass


class AffirmHandlerCallable(Protocol):
    '''
    Handler which receives request to affirm that earlier query of this client
    shall be done.

    See also communication.client.WAIT_AND_RECEIVE_SINGLE_THREAD_WARNING

    Because most of the time such affirmation will require human interaction,
    response of affirm handler needs may need be sent asynchronomusly. Because
    of that affirm handler needs to bound to specific Client object in which it
    will call Client.respond() function --- this binding is done by
    AffirmHandlerGenerator, being the actual type taken by Client.query() method.

    The arguments of AffirmHandlerCallable are:
    response_topic --- topic to which acknowledgement or denial of affirmation
                       shall be sent --- this topic shall be used by handler
                       when calling Client.respond() function.
    message        --- contents of affirm request message
    from_part      --- who has sent the affirm request message --- this shall be
                       used by handler when calling Client.respond().
    message_id     --- affirm request id --- shall be used by handler when
                       calling Client.respond()

    The return value of handler shall be Async() if it will generate response
    ansychronously. In rare cases where answer can be created immediately, it
    can be returned by handler as such.
    '''

    def __call__(self, response_topic: str,
                 message: bytes, from_part: bytes, message_id: bytes) -> Any:
        pass


# TODO the handler generator idea is last resort solution, due to timeouts in
# wait_and_receive requiring moving question asker to separate thread...
# Originally I wanted AffirmHandlerCallable to be
# AffirmHandlerCallable = Callable[[bytes], bool]
# And no need for generator at all. It can be done even with async support, but
# bigger refactoring would be needed for that, so until we have time for that we
# are stuck with generator
class AffirmHandlerGenerator(Protocol):
    '''
    Generator function which will return AffirmHandlerCallable bound to Client
    given as argument. See AffirmHandlerCallable for more details.
    '''

    def __call__(self, __client: Client) -> AffirmHandlerCallable:
        pass


QueryHandlerCallable = Client.QueryHandler.HandlerCallable
