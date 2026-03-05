#!/usr/bin/env python3
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
Module responsible for executing docker configuration commands.
"""
from __future__ import annotations

# Standard imports
import argparse
import ipaddress
import json
import sys
from typing import Any, Callable, Mapping, Optional, Union, cast

# Local imports
import mpa.communication.topics as topics
from mpa.common.logger import Logger
from mpa.common.common import empty_message_wrapper
from mpa.communication import client as com_client
from mpa.communication.client import guarded
from mpa.communication.client import sync, Async
from mpa.communication.client import background
from mpa.communication.common import expect_empty_message
from mpa.communication.common import InvalidParameterError
from mpa.communication.inter_process_lock import InterProcessLock
from mpa.communication.message_parser import (
    get_dict, get_ip46, get_ip46_list, get_optional_bool, get_optional_int, get_str, get_int
)
from mpa.communication.process import run_command, run_command_unchecked
from mpa.config.common import CONFIG_DIR_ROOT
from mpa.docker.common import COMPOSE_FILES_DIR, run_docker_compose, docker_compose_up_async

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")

DOCKER_CONFIG = CONFIG_DIR_ROOT / "docker/daemon.json"
DOCKER_SET_CONFIG_LOCK = InterProcessLock(CONFIG_DIR_ROOT / "mgmtd/docker.set_config.lock", stale_lock_seconds=600)

_parser = argparse.ArgumentParser(prog='Docker config daemon')
com_client.add_command_line_params(_parser)
_args = _parser.parse_args()
_client = com_client.Client(args=_args)


def _docker_restart(restart_iotedge: bool = True, restart_containers: bool = True) -> None:
    if restart_iotedge:
        run_command("iotedge system stop")

    run_command("systemctl restart docker")

    if restart_iotedge:
        run_command_unchecked("docker network rm azure-iot-edge")
        run_command("iotedge system restart")

    if restart_containers:
        compose_dirs = list(COMPOSE_FILES_DIR.glob("*"))
        if len(compose_dirs) == 0:
            return
        
        for d in compose_dirs:
            run_docker_compose("down", cwd=d)
        
        docker_compose_up_async(*compose_dirs)


def docker_dns_get_config(message: bytes) -> Mapping[str, Any]:
    expect_empty_message(message, "docker_dns_get_config()")
    json_data = json.loads(DOCKER_CONFIG.read_text())
    return {"dockerdns": json_data['dns']}


@empty_message_wrapper
def docker_restart(message: bytes) -> None:
    expect_empty_message(message, "docker_restart()")
    _docker_restart(restart_iotedge=True, restart_containers=True)


def docker_dns_add(message: bytes) -> None:
    ip_address = f'{get_ip46(json.loads(message), "ip")}'
    json_data = json.loads(DOCKER_CONFIG.read_text())
    dns_list = [f"{ipaddr}" for ipaddr in get_ip46_list(json_data, 'dns')]

    if ip_address in dns_list:
        raise InvalidParameterError(f"Address {ip_address} was already configured as DNS for docker")

    dns_list.append(ip_address)
    json_data['dns'] = dns_list
    DOCKER_CONFIG.write_text(json.dumps(json_data, indent=4))
    logger.info("Added new dockerdns")


def docker_dns_del(message: bytes) -> None:
    ip_address = f'{get_ip46(json.loads(message), "ip")}'
    json_data = json.loads(DOCKER_CONFIG.read_text())
    dns_list = [f"{ipaddr}" for ipaddr in get_ip46_list(json_data, 'dns')]

    if ip_address not in dns_list:
        raise InvalidParameterError(f"Address {ip_address} is not configured as DNS for docker")

    dns_list.remove(ip_address)
    json_data['dns'] = dns_list
    DOCKER_CONFIG.write_text(json.dumps(json_data, indent=4))
    logger.info("Added new dockerdns")


def docker_dns_set_config(message: bytes, restart_docker: bool = True) -> None:
    config = json.loads(message)
    list_of_ips = [f"{ipaddr}" for ipaddr in get_ip46_list(config, "dockerdns")]
    with DOCKER_SET_CONFIG_LOCK.transaction("Global lock for setting docker config"):
        old_config = json.loads(DOCKER_CONFIG.read_text())
        old_config['dns'] = list_of_ips
        DOCKER_CONFIG.write_text(json.dumps(old_config, indent=4))
        if restart_docker:
            _docker_restart(restart_iotedge=False, restart_containers=False)


def docker_params_get_config(message: bytes) -> Mapping[str, Any]:
    expect_empty_message(message, "docker_params_get_config()")
    json_data = json.loads(DOCKER_CONFIG.read_text())
    params = {}
    if "mtu" in json_data:
        params["dockermtu"] = json_data["mtu"]
    if "debug" in json_data:
        params["dockerdebug"] = json_data["debug"]
    return {"params": params}


def docker_params_set(message: bytes, restart_docker: bool = True) -> None:
    payload = json.loads(message)
    if "params" not in payload:
        return
    json_data = json.loads(DOCKER_CONFIG.read_text())
    params = get_dict(payload, "params")
    incomming_mtu_value = get_optional_int(params, "dockermtu")
    incomming_debug_value = get_optional_bool(params, "dockerdebug")
    logger.info(f"docker_params_set {incomming_mtu_value=} {incomming_debug_value=}")

    if incomming_mtu_value is None:
        json_data.pop("mtu", None)
    else:
        json_data["mtu"] = incomming_mtu_value

    if incomming_debug_value is None:
        json_data.pop("debug", None)
    else:
        json_data["debug"] = incomming_debug_value

    with DOCKER_SET_CONFIG_LOCK.transaction("Global lock for setting docker config"):
        DOCKER_CONFIG.write_text(json.dumps(json_data, indent=4))
        if restart_docker:
            _docker_restart(restart_iotedge=False, restart_containers=False)


def _validate_pool(base: str, size: int) -> None:
    try:
        network = ipaddress.ip_network(base, strict=True)
    except ValueError as e:
        raise InvalidParameterError(f"Invalid CIDR '{base}': {e}")

    if network.version != 4:
        raise InvalidParameterError("Only IPv4 networks are supported")

    if size <= network.prefixlen:
        raise InvalidParameterError(f"Invalid subnet size {size}. Must be larger than base prefix {network.prefixlen}")


def _get_current_pools() -> list[dict[str, str | int]]:
    json_data = json.loads(DOCKER_CONFIG.read_text())
    pools = cast(list[dict[str, str | int]], json_data.get("default-address-pools", []))
    return pools


def _write_pools(pools: list[dict[str, str | int]]) -> None:
    json_data = json.loads(DOCKER_CONFIG.read_text())
    json_data["default-address-pools"] = pools
    DOCKER_CONFIG.write_text(json.dumps(json_data, indent=4))


def docker_network_pools_get_config(message: bytes) -> Mapping[str, Any]:
    expect_empty_message(message, "docker_network_pools_get_config()")
    pools = _get_current_pools()
    return {
        "network_pools": [
            {"base": pool["base"], "size": pool["size"]}
            for pool in pools
        ]
    }


def docker_network_pools_add(message: bytes) -> None:
    data = json.loads(message)
    base = get_str(data, "base")
    size = get_int(data, "size")
    _validate_pool(base, size)
    pools = _get_current_pools()
    if any(str(pool["base"]) == base for pool in pools):
        raise InvalidParameterError(f"Network pool {base} already configured")

    pools.append({"base": base, "size": size})
    _write_pools(pools)


def docker_network_pools_remove(message: bytes) -> None:
    data = json.loads(message)
    base = get_str(data, "base")
    pools = _get_current_pools()
    new_pools = [pool for pool in pools if pool["base"] != base]
    if len(new_pools) == len(pools):
        raise InvalidParameterError(f"Network pool {base} not configured")

    _write_pools(new_pools)


def docker_network_pools_clear(message: bytes) -> None:
    expect_empty_message(message, "docker_network_pools_clear()")
    _write_pools([])


def docker_network_pools_set_config(message: bytes, restart_docker: bool = True) -> None:
    config = json.loads(message)
    pools = config.get("network_pools")
    if pools is None:
        return

    validated_pools: list[dict[str, str | int]] = []
    for pool in pools:
        base = get_str(pool, "base")
        size = get_int(pool, "size")
        _validate_pool(base, size)
        validated_pools.append({"base": base, "size": size})

    with DOCKER_SET_CONFIG_LOCK.transaction("Global lock for setting docker network pools"):
        _write_pools(validated_pools)
        if restart_docker:
            _docker_restart()


def docker_set_config(query_message: bytes, from_part: bytes, query_message_id: bytes) -> Async:
    # We are sending 2 messages in a row --- one to ourselves (to set dns), second to docker.compose
    # We cannot directly process dns setting here because of the way locking and restarting of
    # docker is performed there --- doing it in background thread would prevent proper # error
    # reporting from locking, # and doing it in foreground prevents processing of other messages in
    # this daemon for to long
    config = get_dict(json.loads(query_message), "docker")

    def respond(message: Union[bytes, str]) -> Optional[bool]:
        _client.respond(topics.docker.set_config + com_client.RESPONSE_SUFFIX, message, from_part, query_message_id)
        if isinstance(message, str):
            return False
        return None

    docker_params_set(json.dumps(config).encode(), restart_docker=False)
    docker_dns_set_config(json.dumps(config).encode(), restart_docker=False)
    docker_network_pools_set_config(json.dumps(config).encode(), restart_docker=True)
    _client.query(topics.docker.compose.set_config, config, handler=respond)
    return Async()


def main() -> None:
    def in_bg(topic: str, fun: com_client.SyncHandlerCallable, post_respond: Optional[Callable[[Any], None]] = None) -> None:
        messages[topic] = background(fun, com_client.respond_to(_client, topic), post_respond=post_respond)

    messages = {}
    in_bg(topics.docker.restart, guarded(docker_restart))
    messages[topics.docker.dns.add] = guarded(sync(docker_dns_add))
    messages[topics.docker.dns.delete] = guarded(sync(docker_dns_del))
    messages[topics.docker.dns.get_config] = guarded(sync(docker_dns_get_config))
    in_bg(topics.docker.dns.set_config, guarded(docker_dns_set_config))
    messages[topics.docker.params.set] = guarded(sync(docker_params_set))
    messages[topics.docker.params.get_config] = guarded(sync(docker_params_get_config))
    messages[topics.docker.params.set_config] = guarded(sync(docker_params_set))
    messages[topics.docker.set_config] = guarded(docker_set_config)
    in_bg(topics.docker.network_pools.set_config, guarded(docker_network_pools_set_config))
    messages[topics.docker.network_pools.get_config] = guarded(sync(docker_network_pools_get_config))
    messages[topics.docker.network_pools.add] = guarded(sync(docker_network_pools_add))
    messages[topics.docker.network_pools.remove] = guarded(sync(docker_network_pools_remove))
    messages[topics.docker.network_pools.clear] = guarded(sync(docker_network_pools_clear))

    _client.register_responders(messages)

    while True:
        _client.wait_and_receive()


if __name__ == "__main__":
    main()
