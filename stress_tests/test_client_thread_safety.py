#
# Copyright (c) 2026 Contributors to the Eclipse Foundation.
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
Thread safety of mpa.communication.client.Client. See client_scenarios.py for
description of scenarios and README.md for how to run them.
"""
from typing import Any, Dict

from conftest import ScenarioRunner


def assert_clean(result: Dict[str, Any]) -> None:
    assert result["violations"] == [], "\n".join(["Concurrent socket use detected:", *result["violations"][:5]])
    assert result["errors"] == [], "\n".join(["Exceptions in threads:", *result["errors"][:5]])
    assert result["log"] == [], "\n".join(["Client logged warnings/errors:", *result["log"][:10]])


def test_concurrent_sends_are_published_intact(run_scenario: ScenarioRunner) -> None:
    result = run_scenario("concurrent_sends")
    assert_clean(result)
    assert result["malformed"] == [], "\n".join(["Forwarder published malformed messages:", *result["malformed"][:5]])
    assert result["missing"] == 0
    assert result["duplicate_ids"] == 0


def test_sends_from_other_thread_while_receiving(run_scenario: ScenarioRunner) -> None:
    result = run_scenario("sends_while_receiving")
    assert_clean(result)
    assert result["missing"] == 0
    assert result["req_used_by"] == ["receiver"], "Only wait_and_receive() shall ping"


def test_req_requests_from_other_thread_while_receiving(run_scenario: ScenarioRunner) -> None:
    result = run_scenario("req_requests_while_receiving")
    assert_clean(result)
    assert result["watchers"] == 1001 and result["watcher_calls"] == 0


def test_only_receiving_thread_pings(run_scenario: ScenarioRunner) -> None:
    result = run_scenario("requests_while_receiving")
    assert_clean(result)
    assert result["pinged_by"] == ["receiver"]


def test_second_receiving_thread_does_not_receive(run_scenario: ScenarioRunner) -> None:
    result = run_scenario("two_receivers")
    assert_clean(result)
    assert result["dispatched_by"] == ["receiver"], \
        f"Second wait_and_receive() call dispatched messages: {result['second_receiver_outcomes']}"
    assert result["missing"] == 0


def test_queries_from_other_threads_while_receiving(run_scenario: ScenarioRunner) -> None:
    result = run_scenario("queries_while_receiving")
    assert_clean(result)
    assert result["missing"] == [] and result["wrong"] == []


def test_registering_handler_while_handler_of_same_topic_runs(run_scenario: ScenarioRunner) -> None:
    result = run_scenario("register_while_dispatching")
    assert result["handler_called"]
    assert_clean(result)
    assert result["registered_while_running"] == [True], "Registration waited for running handler (lock held while calling it?)"
