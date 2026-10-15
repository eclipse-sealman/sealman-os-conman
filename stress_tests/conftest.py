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
Fixtures running real forwarder (message_router) for stress tests, see README.md.

Environment variables:
  MPA_TEST_FORWARDER       --- path to already built forwarder binary
  MPA_FORWARDER_BUILD_DIR  --- where forwarder is built if MPA_TEST_FORWARDER is not given
                               (stress_tests/.build by default)
  MPA_FORWARDER_MAKE_ARGS  --- extra make arguments used when forwarder is built
"""
import grp
import multiprocessing
import os
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterator

import pytest

import client_scenarios

HERE = Path(__file__).parent
MESSAGE_ROUTER = HERE.parent / "message_router"
BUILD_DIR = Path(os.environ.get("MPA_FORWARDER_BUILD_DIR", HERE / ".build"))
SCENARIO_TIMEOUT_S = 120


def _build_forwarder() -> Path:
    build = BUILD_DIR / "message_router"
    # copy2 keeps mtimes, so make rebuilds only what changed in message_router
    shutil.copytree(MESSAGE_ROUTER, build, dirs_exist_ok=True)
    command = ["make", "-j", str(os.cpu_count() or 1), "forwarder", *shlex.split(os.environ.get("MPA_FORWARDER_MAKE_ARGS", ""))]
    done = subprocess.run(command, cwd=build, capture_output=True, text=True)
    if done.returncode != 0:
        pytest.fail(f"Building forwarder failed ({shlex.join(command)}):\n{done.stdout}\n{done.stderr}", pytrace=False)
    return build / "forwarder"


@pytest.fixture(scope="session")
def forwarder_binary() -> Path:
    try:
        grp.getgrgid(os.getegid())
    except KeyError:
        pytest.fail(f"Group {os.getegid()} of this process has no entry in group database, but forwarder needs it "
                    "(e.g. in docker do not use --user with group unknown to the image, see README.md)", pytrace=False)
    configured = os.environ.get("MPA_TEST_FORWARDER")
    if configured:
        if not Path(configured).is_file():
            pytest.fail(f"MPA_TEST_FORWARDER={configured} does not exist", pytrace=False)
        return Path(configured)
    return _build_forwarder()


@pytest.fixture
def forwarder_dir(forwarder_binary: Path) -> Iterator[Path]:
    # ipc:// paths are limited to ~107 bytes
    directory = Path(tempfile.mkdtemp(prefix="mpa-st-", dir="/tmp" if len(tempfile.gettempdir()) > 60 else None))
    log = (directory / "forwarder.log").open("w")
    process = subprocess.Popen([forwarder_binary, "--dir", directory, "--name", "test"], stdout=log, stderr=subprocess.STDOUT)
    try:
        sockets = [directory / f"test.{kind}" for kind in ("req", "push", "sub")]
        deadline = time.monotonic() + 10
        while not all(sock.exists() for sock in sockets):
            if process.poll() is not None or time.monotonic() > deadline:
                pytest.fail(f"Forwarder did not start (exit code {process.poll()}):\n{(directory / 'forwarder.log').read_text()}",
                            pytrace=False)
            time.sleep(0.01)
        yield directory
        assert process.poll() is None, f"Forwarder died during test:\n{(directory / 'forwarder.log').read_text()}"
    finally:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        log.close()
        shutil.rmtree(directory, ignore_errors=True)


ScenarioRunner = Callable[..., Dict[str, Any]]


@pytest.fixture
def run_scenario(forwarder_dir: Path) -> ScenarioRunner:
    """Runs client_scenarios.SCENARIOS[name] in spawned process and returns its result."""
    def runner(name: str, **kwargs: Any) -> Dict[str, Any]:
        context = multiprocessing.get_context("spawn")
        results = context.Queue()
        process = context.Process(target=client_scenarios.run, args=(name, str(forwarder_dir), results, kwargs), name=name)
        process.start()
        try:
            result: Dict[str, Any] = results.get(timeout=SCENARIO_TIMEOUT_S)
        except Exception:
            process.join(1)
            if process.exitcode is None:
                process.kill()
                process.join()
                pytest.fail(f"Scenario {name} did not finish in {SCENARIO_TIMEOUT_S}s (deadlock?)", pytrace=False)
            signal_info = f" ({signal.Signals(-process.exitcode).name})" if process.exitcode < 0 else ""
            pytest.fail(f"Scenario {name} process crashed with exit code {process.exitcode}{signal_info} --- "
                        "SIGABRT is typical for libzmq assertion triggered by socket used from two threads at once",
                        pytrace=False)
        process.join(10)
        if "scenario_error" in result:
            pytest.fail(f"Scenario {name} failed to run:\n{result['scenario_error']}", pytrace=False)
        return result
    return runner
