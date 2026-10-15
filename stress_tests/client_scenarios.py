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
Scenarios exercising mpa.communication.client.Client from many threads against
real forwarder. Each scenario runs in a separate (spawned) process, because
libzmq sockets used concurrently from two threads may abort the whole process.

Inside that process all zmq sockets are replaced by CheckingSocket, which
refuses (raises ConcurrentSocketUseError without touching libzmq) when a
socket is entered by a thread while another thread is still using it. For REQ
sockets the whole request-reply exchange counts as single use. This turns
undefined behaviour (which often stays invisible) into deterministic failures.

Every scenario returns a dict which test asserts on. Common keys:
  errors     --- exceptions caught in any thread
  violations --- concurrent socket uses detected by CheckingSocket
  log        --- WARNING and above records logged by mpa modules
"""
from __future__ import annotations

import functools
import json
import logging
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, cast

import zmq

Result = Dict[str, Any]

_violations: List[str] = []
_violations_lock = threading.Lock()


class ConcurrentSocketUseError(AssertionError):
    pass


def _thread_name(ident: Optional[int]) -> str:
    for thread in threading.enumerate():
        if thread.ident == ident:
            return thread.name
    return str(ident)


class CheckingSocket(zmq.Socket):  # type: ignore
    """zmq.Socket refusing to be used by two threads at the same time"""
    # pyzmq maps unknown attributes to socket options, so we need to declare them on class level
    _check_lock: Optional[threading.Lock] = None
    _users: Optional[Dict[int, int]] = None
    _req_owner: Optional[int] = None
    used_by: Optional[Set[str]] = None
    pinged_by: Optional[Set[str]] = None

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._check_lock = threading.Lock()
        self._users = {}
        self.used_by = set()
        self.pinged_by = set()

    def _enter(self, what: str) -> None:
        assert self._check_lock is not None and self._users is not None
        me = threading.get_ident()
        with self._check_lock:
            others = [ident for ident in self._users if ident != me]
            if not others and self._req_owner is not None and self._req_owner != me:
                others = [self._req_owner]
            if others:
                message = (f"{what} on {self.get_type_name()} socket in thread {_thread_name(me)} "
                           f"while thread {_thread_name(others[0])} uses it")
                with _violations_lock:
                    _violations.append(message)
                raise ConcurrentSocketUseError(message)
            self._users[me] = self._users.get(me, 0) + 1
            assert self.used_by is not None
            self.used_by.add(threading.current_thread().name)

    def _exit(self) -> None:
        assert self._check_lock is not None and self._users is not None
        me = threading.get_ident()
        with self._check_lock:
            self._users[me] -= 1
            if self._users[me] == 0:
                del self._users[me]

    def get_type_name(self) -> str:
        return zmq.SocketType(cast(int, super().get(zmq.TYPE))).name

    def _checked(self, what: str, function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        self._enter(what)
        try:
            return function(*args, **kwargs)
        finally:
            self._exit()

    def send(self, *args: Any, **kwargs: Any) -> Any:
        return self._checked("send", super().send, *args, **kwargs)

    def send_multipart(self, msg_parts: Any, *args: Any, **kwargs: Any) -> Any:
        retval = self._checked("send_multipart", super().send_multipart, msg_parts, *args, **kwargs)
        if super().get(zmq.TYPE) == zmq.REQ:
            self._req_owner = threading.get_ident()
            if msg_parts[0] == b"PING":
                assert self.pinged_by is not None
                self.pinged_by.add(threading.current_thread().name)
        return retval

    def send_string(self, *args: Any, **kwargs: Any) -> Any:
        retval = self._checked("send_string", super().send_string, *args, **kwargs)
        if super().get(zmq.TYPE) == zmq.REQ:
            self._req_owner = threading.get_ident()
        return retval

    def recv(self, *args: Any, **kwargs: Any) -> Any:
        retval = self._checked("recv", super().recv, *args, **kwargs)
        if super().get(zmq.TYPE) == zmq.REQ and not super().get(zmq.RCVMORE):
            self._req_owner = None
        return retval

    def poll(self, *args: Any, **kwargs: Any) -> Any:
        return self._checked("poll", super().poll, *args, **kwargs)

    def get(self, *args: Any, **kwargs: Any) -> Any:
        return self._checked("get", super().get, *args, **kwargs)

    def set(self, *args: Any, **kwargs: Any) -> Any:
        return self._checked("set", super().set, *args, **kwargs)

    getsockopt = get
    setsockopt = set

    def subscribe(self, topic: Any) -> None:
        self._checked("subscribe", super().subscribe, topic)

    def unsubscribe(self, topic: Any) -> None:
        self._checked("unsubscribe", super().unsubscribe, topic)


class CheckingPoller(zmq.Poller):
    """zmq.Poller which marks registered CheckingSockets as used while polling"""

    def poll(self, timeout: Optional[int] = None) -> Any:
        entered: List[CheckingSocket] = []
        try:
            for sock, _flags in self.sockets:
                if isinstance(sock, CheckingSocket):
                    sock._enter("Poller.poll")
                    entered.append(sock)
            return super().poll(timeout)
        finally:
            for sock in entered:
                sock._exit()


class RecordingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.records: List[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(f"{record.name}: {record.getMessage()}"[:300])


_log = RecordingHandler()


def _install_checks() -> None:
    zmq.Context._socket_class = CheckingSocket  # type: ignore[misc]
    zmq.Poller = CheckingPoller  # type: ignore[misc]
    # Avoid journal (it may be missing, e.g. in docker) and keep only warnings for the result
    import mpa.communication.client  # noqa: F401 (creates mpa loggers)
    for name, logger in logging.root.manager.loggerDict.items():
        if name.startswith("mpa") and isinstance(logger, logging.Logger):
            logger.handlers = [_log]


class Errors:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.items: List[str] = []

    def add(self, where: str, exc: BaseException) -> None:
        with self.lock:
            self.items.append(f"{where}: {exc!r}\n{''.join(traceback.format_tb(exc.__traceback__)[-3:])}")

    def run(self, where: str, function: Callable[[], None]) -> Callable[[], None]:
        def wrapped() -> None:
            try:
                function()
            except BaseException as exc:  # pylint: disable=broad-except
                self.add(where, exc)
        return wrapped


def make_client(forwarder_dir: Path, **kwargs: Any) -> Any:
    from mpa.communication.client import Client

    def not_allowed(message: bytes, from_part: bytes, message_id: bytes) -> None:
        pass
    return Client(directory=forwarder_dir, group="test", allowed_messages=forwarder_dir / "no_allowed_messages",
                  not_allowed_handler=not_allowed, **kwargs)


class Receiver:
    """Runs wait_and_receive() of the client in background thread until stopped"""

    def __init__(self, client: Any, errors: Errors, name: str = "receiver") -> None:
        self.client = client
        self.errors = errors
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.__loop, name=name, daemon=True)

    def __loop(self) -> None:
        while not self.stop.is_set():
            try:
                self.client.wait_and_receive(timeout_ms=100)
            except self.client.TimeoutError:
                pass
            except Exception as exc:  # pylint: disable=broad-except
                self.errors.add(self.thread.name, exc)

    def __enter__(self) -> Receiver:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop.set()
        self.thread.join(5)
        if self.thread.is_alive():
            self.errors.add(self.thread.name, RuntimeError("receiver did not stop (deadlock?)"))


def wait_until(condition: Callable[[], bool], timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.01)
    return condition()


def run_threads(errors: Errors, count: int, target: Callable[[int], None], *, timeout_s: float = 20) -> None:
    threads = [threading.Thread(target=errors.run(f"worker{n}", functools.partial(target, n)), name=f"worker{n}", daemon=True)
               for n in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout_s)
        if thread.is_alive():
            errors.add(thread.name, RuntimeError("worker did not finish (deadlock?)"))


def _finish(errors: Errors, **result: Any) -> Result:
    with _violations_lock:
        violations = list(_violations)
    return {"errors": errors.items, "violations": violations, "log": _log.records, **result}


def concurrent_sends(forwarder_dir: Path, threads: int = 4, per_thread: int = 300) -> Result:
    """Many threads call send() on one client, raw SUB socket checks what forwarder published."""
    errors = Errors()
    client = make_client(forwarder_dir)
    context = zmq.Context()
    sub = context.socket(zmq.SUB, socket_class=zmq.Socket)
    sub.connect(f"ipc://{forwarder_dir}/test.sub")
    sub.subscribe(b"thread.")
    # Wait for subscription to reach forwarder
    if not wait_until(lambda: client.send("thread.probe") is None and bool(sub.poll(50)), 5):
        raise RuntimeError("Subscription of raw SUB socket was not established")
    while sub.poll(100):
        sub.recv_multipart()

    def worker(n: int) -> None:
        for i in range(per_thread):
            client.send(f"thread.{n}", {"n": n, "i": i})

    run_threads(errors, threads, worker)

    malformed: List[str] = []
    seen: Set[Tuple[int, int]] = set()
    message_ids: List[bytes] = []
    while sub.poll(500):
        frames = sub.recv_multipart()
        if (len(frames) != 5 or len(frames[1]) != 8 or frames[2] != client.req.pub_id
                or frames[3][:1] != b"M" or len(frames[3]) != 4):
            malformed.append(repr(frames)[:200])
            continue
        message_ids.append(frames[3])
        body = json.loads(frames[4])
        seen.add((body["n"], body["i"]))
    sub.close()
    expected = {(n, i) for n in range(threads) for i in range(per_thread)}
    return _finish(errors, malformed=malformed, missing=len(expected - seen),
                   duplicate_ids=len(message_ids) - len(set(message_ids)))


def sends_while_receiving(forwarder_dir: Path, per_thread: int = 1000) -> Result:
    """
    Receiver thread is in wait_and_receive(), worker thread send()s messages
    the client itself listens to. Short ping period makes pings frequent.
    Pinging is job of wait_and_receive(), so worker shall not touch Req socket.
    """
    errors = Errors()
    client = make_client(forwarder_dir)
    client.req.ping_period_ms = 5
    received: List[bytes] = []
    client.register_trivial_handler("echo", received.append)
    with Receiver(client, errors):
        if not wait_until(lambda: client.send("echo", "probe") is None and len(received) > 0, 5):
            raise RuntimeError("Probe message was not received")
        received.clear()
        client.req.sock.used_by.clear()

        def worker(n: int) -> None:
            for i in range(per_thread):
                client.send("echo", {"n": n, "i": i})
                time.sleep(0.0005)

        run_threads(errors, 1, worker)
        expected = per_thread
        wait_until(lambda: len(received) >= expected, 5)
    return _finish(errors, missing=max(0, expected - len(received)), req_used_by=sorted(client.req.sock.used_by))


def req_requests_while_receiving(forwarder_dir: Path, requests: int = 1000) -> Result:
    """
    Receiver thread pings forwarder from wait_and_receive() while worker
    thread sends other requests on Req socket. Here it is EXISTS sent by
    register_topic_watcher() for already subscribed topic (so Sub socket is
    not touched), similar requests are sent by register_responding_handler()
    and by queries with affirm handlers.
    """
    errors = Errors()
    client = make_client(forwarder_dir)
    client.req.ping_period_ms = 5
    states: List[bool] = []  # stays empty, as nobody subscribes "watched"
    client.register_topic_watcher("watched", states.append)

    def worker(n: int) -> None:
        for _ in range(requests):
            client.register_topic_watcher("watched", lambda state: states.append(state))

    with Receiver(client, errors):
        run_threads(errors, 1, worker)
    return _finish(errors, watchers=len(client.handlers.topic_watcher["watched"]), watcher_calls=len(states))


def requests_while_receiving(forwarder_dir: Path, requests: int = 200) -> Result:
    """
    Worker thread uses public methods which need Req socket, while receiver
    thread is in wait_and_receive(). Only receiver shall ping forwarder (and
    reconnect if needed).
    """
    from mpa.communication.client import guarded, sync

    errors = Errors()
    client = make_client(forwarder_dir)
    client.req.ping_period_ms = 5

    def watcher(subscribed_topic: str, response_topic: Optional[str] = None) -> None:
        pass

    def worker(n: int) -> None:
        for i in range(requests):
            client.exists(["nobody"])
            client.register_responding_handler(f"handled{i}", guarded(sync(lambda message: None)))
            client.register_subscription_watcher(f"watched{i}", watcher)
            client.unregister_subscription_watcher(f"watched{i}", watcher)

    with Receiver(client, errors):
        if not wait_until(lambda: len(client.req.sock.pinged_by) > 0, 5):
            raise RuntimeError("Receiver did not ping")
        run_threads(errors, 1, worker)
    return _finish(errors, pinged_by=sorted(client.req.sock.pinged_by))


def two_receivers(forwarder_dir: Path, messages: int = 5) -> Result:
    """
    Only one thread may receive at a time. Receiver thread is kept inside
    wait_and_receive() by blocked handler, while main thread calls
    wait_and_receive() too, with messages waiting to be received. Second
    call shall be prevented from receiving, so all messages shall be
    dispatched by receiver.
    """
    errors = Errors()
    client = make_client(forwarder_dir)
    sender = make_client(forwarder_dir, public_id="sender")
    handler_running = threading.Event()
    release = threading.Event()
    dispatched_by: Set[str] = set()
    received: List[bytes] = []
    second_receiver_outcomes: List[str] = []

    def blocking(message: bytes) -> None:
        if not handler_running.is_set():
            handler_running.set()
            release.wait(5)

    def echo(message: bytes) -> None:
        dispatched_by.add(threading.current_thread().name)
        received.append(message)

    client.register_trivial_handler("block", blocking)
    client.register_trivial_handler("echo", echo)
    with Receiver(client, errors):
        if not wait_until(lambda: sender.send("block") is None and handler_running.is_set(), 5):
            raise RuntimeError("Blocking handler was not called")
        for i in range(messages):
            sender.send("echo", i)
        for _ in range(messages):
            try:
                client.wait_and_receive(timeout_ms=300)
                second_receiver_outcomes.append("returned")
            except Exception as exc:  # pylint: disable=broad-except
                second_receiver_outcomes.append(repr(exc))
        release.set()
        wait_until(lambda: len(received) >= messages, 5)
    return _finish(errors, dispatched_by=sorted(dispatched_by), missing=max(0, messages - len(received)),
                   second_receiver_outcomes=second_receiver_outcomes)


def queries_while_receiving(forwarder_dir: Path, threads: int = 2, per_thread: int = 50) -> Result:
    """
    Responder client answers echo queries. Requester client runs
    wait_and_receive() in its own thread while other threads send queries
    and wait for responses.
    """
    from mpa.communication.client import guarded, sync

    errors = Errors()
    responder = make_client(forwarder_dir, public_id="echo")
    responder.register_responders({"echo": guarded(sync(lambda message: json.loads(message)))})
    requester = make_client(forwarder_dir, public_id="asker")
    missing: List[str] = []
    wrong: List[str] = []

    def worker(n: int) -> None:
        for i in range(per_thread):
            done = threading.Event()
            responses: List[Any] = []

            def handler(message: Any) -> Optional[bool]:
                responses.append(message)
                done.set()
                return None if isinstance(message, bytes) else False

            requester.query("echo", {"n": n, "i": i}, handler)
            if not done.wait(3):
                missing.append(f"{n}/{i}")
                return  # no point to wait for next ones
            if not isinstance(responses[0], bytes) or json.loads(responses[0]) != {"n": n, "i": i}:
                wrong.append(f"{n}/{i}: {responses[0]!r}")

    with Receiver(responder, errors, "responder"), Receiver(requester, errors, "requester"):
        run_threads(errors, threads, worker, timeout_s=60)
    return _finish(errors, missing=missing, wrong=wrong)


def register_while_dispatching(forwarder_dir: Path) -> Result:
    """
    Other thread registers handler for a topic while handler for same topic
    is being called by wait_and_receive(). Registration must neither break
    dispatching nor wait for the running handler to finish.
    """
    errors = Errors()
    client = make_client(forwarder_dir)
    sender = make_client(forwarder_dir, public_id="sender")
    handler_running = threading.Event()
    registered = threading.Event()
    registered_while_running: List[bool] = []

    def first(message: bytes) -> None:
        if not handler_running.is_set():
            handler_running.set()
            registered_while_running.append(registered.wait(2))

    def second(message: bytes) -> None:
        pass

    def register() -> None:
        if handler_running.wait(5):
            client.register_trivial_handler("topic", second)
            registered.set()

    client.register_trivial_handler("topic", first)
    registering = threading.Thread(target=errors.run("registering", register), name="registering", daemon=True)
    registering.start()
    with Receiver(client, errors):
        wait_until(lambda: sender.send("topic") is None and handler_running.is_set(), 5)
        registering.join(10)
        # Let receiver finish dispatching of the message during which we registered
        time.sleep(0.3)
    return _finish(errors, handler_called=handler_running.is_set(), registered_while_running=registered_while_running)


SCENARIOS: Dict[str, Callable[..., Result]] = {
    "concurrent_sends": concurrent_sends,
    "sends_while_receiving": sends_while_receiving,
    "req_requests_while_receiving": req_requests_while_receiving,
    "requests_while_receiving": requests_while_receiving,
    "two_receivers": two_receivers,
    "queries_while_receiving": queries_while_receiving,
    "register_while_dispatching": register_while_dispatching,
}


def run(name: str, forwarder_dir: str, results: Any, kwargs: Dict[str, Any]) -> None:
    """Entry point of spawned process"""
    _install_checks()
    try:
        result = SCENARIOS[name](Path(forwarder_dir), **kwargs)
    except BaseException as exc:  # pylint: disable=broad-except
        result = {"scenario_error": "".join(traceback.format_exception(exc)), "errors": [], "violations": list(_violations),
                  "log": _log.records}
    results.put(result)
    sys.stdout.flush()
