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
import json
import sys
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed, Future, TimeoutError as cf_TimeoutError
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, MutableMapping, Optional

# Third party imports
import tenacity
from docker.client import DockerClient  # type: ignore

# Local imports
import mpa.communication.topics as topics
from mpa.config.configfiles import ConfigFiles
from mpa.communication import client as com_client
from mpa.communication.client import background
from mpa.communication.client import guarded
from mpa.communication.client import sync
from mpa.communication.common import expect_empty_message
from mpa.communication.common import InvalidParameterError, InvalidPayloadError, InvalidPreconditionError
from mpa.communication.common import merge_dictionaries
from mpa.communication.message_parser import get_dict, get_optional_bool, get_str, get_optional_str
from mpa.communication.process import run_command
from mpa.common.logger import Logger
from mpa.common.common import RESPONSE_OK

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")

COMPOSED_HOME = Path("/home/composed")
COMPOSE_FILES_DIR = COMPOSED_HOME / "containers"
config_files = ConfigFiles()
USERS_DOCKER_CONFIG_FILE = config_files.add("docker_config", ".docker/config.json",
                                            config_dir_root=COMPOSED_HOME, is_expected=False)

_parser = argparse.ArgumentParser(prog='Docker config daemon')
com_client.add_command_line_params(_parser)
_args = _parser.parse_args()
_client = com_client.Client(args=_args)


def run_docker_compose(cmd: str, **kwargs: Any) -> None:
    run_command(f"docker compose {cmd}", **kwargs)


def validate_compose_file(compose_dir: Path) -> None:
    """
    Executes docker compose config
    """
    run_docker_compose("config", cwd=compose_dir)


@tenacity.retry(
    wait=tenacity.wait_fixed(3),
    stop=tenacity.stop_after_attempt(3),
    reraise=True,
)
def docker_compose_up(compose_dir: Path, force_recreate: bool = False) -> None:
    """"
    Executes docker compose up -d
    """
    run_docker_compose(f"up -d {'--force-recreate' if force_recreate else ''}", cwd=compose_dir)


def compose_callback(future: Future[bytes]) -> None:
    logger.info(f"Future ({threading.get_ident()}) has finished: {future.result()=} {future.exception()=}")


def docker_compose_up_async(*compose_dirs: Path, force_recreate: bool = False, timeout: int = 15) -> dict[str, str]:
    """
    Executes multiple docker compose up -d in a thread pool.

    If there are threads downloading given image in the background then calling this function again will not
    duplicate the download - it only happens once. On the other hand the composition process happens in every thread
    and they will race with each other. Only one will succeed and return a successful result (the others will fail with
    the information that a given container already exists).
    """
    exe = ThreadPoolExecutor(max_workers=len(compose_dirs))
    futures = {exe.submit(docker_compose_up, compose_dir, force_recreate): compose_dir.name for compose_dir in compose_dirs}

    for future in futures:
        future.add_done_callback(compose_callback)  # type: ignore

    results = {}
    try:
        for future in as_completed(futures, timeout=timeout):
            name = futures[future]
            if future.exception() is not None:
                results[name] = str(future.exception())
            else:
                results[name] = RESPONSE_OK
    except cf_TimeoutError:
        for future in futures:
            name = futures[future]
            if name not in results:
                results[name] = f"{RESPONSE_OK} Composition continues in the background"

    exe.shutdown(wait=False)
    return results


def docker_compose_status(message: bytes) -> Mapping[str, str]:
    expect_empty_message(message, "docker_compose_status()")
    running_containers = DockerClient.from_env().containers.list()
    docker_list = " ".join(
        container.name for container in running_containers
        if "net.azure-devices.edge.owner" not in container.labels
    )
    docker_compose_file = run_command(f"autocompose {docker_list}").stdout.decode()
    return {"name": "compose-status", "compose_file": docker_compose_file}


def docker_compose_get(message: bytes) -> Mapping[str, str]:
    name = get_str(json.loads(message), "name")
    compose_dir = COMPOSE_FILES_DIR / name
    if not compose_dir.exists():
        raise InvalidPreconditionError(f"No such compose file: {name}")

    return {"name": name, "compose_file": (compose_dir / 'docker-compose.yml').read_text()}


def docker_compose_add(message: bytes) -> dict[str, str]:
    decoded = json.loads(message)
    name = get_str(decoded, "name")
    yaml = get_str(decoded, "compose_file")
    compose_dir = COMPOSE_FILES_DIR / name
    if compose_dir.exists():
        raise InvalidPreconditionError(f"Compose file '{name}' already exists. You need to remove it before adding.")

    compose_dir.mkdir()
    compose_file = compose_dir / 'docker-compose.yml'
    compose_file.write_text(yaml)
    validate_compose_file(compose_dir)
    return docker_compose_up_async(compose_dir)


def start_all_compositions(name: str = "*", force_recreate: bool = False) -> dict[str, str]:
    compose_dirs = list(COMPOSE_FILES_DIR.glob(name))
    if len(compose_dirs) == 0:
        return {}

    for compose_dir in compose_dirs:
        validate_compose_file(compose_dir)

    return docker_compose_up_async(*compose_dirs, force_recreate=force_recreate)


def del_compose_dir(compose_dir: Path, missing_ok: bool = False) -> None:
    """
    Executes docker compose stop and docker compose rm -f
    """
    if not compose_dir.exists():
        if missing_ok:
            return

        raise InvalidPreconditionError(f"No such compose file: {compose_dir.name}")

    try:
        run_docker_compose("stop", cwd=compose_dir)
        run_docker_compose("rm -f", cwd=compose_dir)
    finally:
        shutil.rmtree(compose_dir)


def docker_compose_del(message: bytes) -> None:
    del_compose_dir(COMPOSE_FILES_DIR / get_str(json.loads(message), "name"))


def docker_compose_recreate(message: bytes) -> dict[str, str] | str:
    """
    Executes docker-compose up -d --force-recreate in a thread pool
    """
    name = get_str(json.loads(message), "name")
    results = start_all_compositions(name, force_recreate=True)
    errors = {k: v for k, v in results.items() if not v.startswith(RESPONSE_OK)}
    if errors:
        raise RuntimeError(f"Failed to recreate all compositions: {errors}")

    return results if results else RESPONSE_OK


def read_users_docker_config_file() -> MutableMapping[str, Any]:
    if not USERS_DOCKER_CONFIG_FILE.parent.exists():
        USERS_DOCKER_CONFIG_FILE.parent.mkdir()
    try:
        data: Dict[str, Any] = json.loads(USERS_DOCKER_CONFIG_FILE.read_text())
        # Historically we could have created those files as 'mgmtd' user ---
        # until we are sure that no more such files exist in the field we need
        # to check for wrong user and recreate file
        if USERS_DOCKER_CONFIG_FILE.owner() != "composed":
            USERS_DOCKER_CONFIG_FILE.unlink()
            USERS_DOCKER_CONFIG_FILE.write_text(json.dumps(data, indent=4))
    except FileNotFoundError:
        data = {}
    return data


def write_users_docker_config_file(data: MutableMapping[str, Any]) -> None:
    if data:
        USERS_DOCKER_CONFIG_FILE.write_text(json.dumps(data, indent=4))
    else:
        USERS_DOCKER_CONFIG_FILE.unlink(missing_ok=True)


def docker_compose_set_config(message: bytes) -> str:
    decoded_message = json.loads(message)
    decoded = get_dict(decoded_message, "compose_files")
    composed_docker_config = decoded_message.get("compose_docker_config")
    if composed_docker_config is not None:
        _ = read_users_docker_config_file()
        write_users_docker_config_file(composed_docker_config)
    for compose_dir in COMPOSE_FILES_DIR.glob('*'):
        if compose_dir.name not in decoded:
            del_compose_dir(compose_dir)
    for name, yaml in decoded.items():
        compose_dir = COMPOSE_FILES_DIR / name
        del_compose_dir(compose_dir, missing_ok=True)
        compose_dir.mkdir()
        (compose_dir / "docker-compose.yml").write_text(yaml)

    results = start_all_compositions()
    errors = {k: v for k, v in results.items() if not v.startswith(RESPONSE_OK)}
    if errors:
        raise InvalidPayloadError(f"Failed to start all compositions: {errors}")

    # do we want '\n' or ' '?
    # check MPA-1612 for reference
    return f"{RESPONSE_OK} {results}" if len(results) else RESPONSE_OK


def docker_compose_get_config(message: bytes) -> Mapping[str, Any]:
    expect_empty_message(message, "docker_compose_get_config()")
    compose_files = {}
    for compose_dir in COMPOSE_FILES_DIR.glob('*'):
        compose_files[compose_dir.name] = (compose_dir / "docker-compose.yml").read_text()
    config = {"compose_files": compose_files}
    data = read_users_docker_config_file()
    if data:
        return {**config, "compose_docker_config": data}
    return config


def docker_compose_auth_add(message: bytes) -> None:
    new_data = json.loads(message)

    data = read_users_docker_config_file()
    if "auths" in data:
        data["auths"].update(new_data["auths"])
    else:
        data["auths"] = new_data["auths"]
    write_users_docker_config_file(data)


def docker_compose_auth_remove(message: bytes) -> None:
    new_data = json.loads(message)

    try:
        data = read_users_docker_config_file()
        if "auths" in data:
            data["auths"].pop(new_data["url"])
            write_users_docker_config_file(data)
    except KeyError:
        raise InvalidParameterError(f"The url provided as parameter `{new_data['url']}` is not present in config.")


# TODO remove possible code duplication with mgmtd-devicy.py:add_proxy
def docker_compose_proxy_add(message: bytes) -> None:
    docker_config_data = read_users_docker_config_file()
    proxy_data = json.loads(message)
    proxies = get_dict(proxy_data, 'proxy_servers')
    reload_daemons = get_optional_bool(proxy_data, 'reload_daemons')
    if reload_daemons is None:
        reload_daemons = True
    new_proxy_docker_config: Dict[str, Any] = {"proxies": {"default": {}}}

    key_prefixes = ('http', 'https')

    def key(prefix: str) -> str:
        return f'{prefix}_proxy'

    def docker_key(prefix: str) -> str:
        return f'{prefix}Proxy'

    keys = list(key(prefix) for prefix in key_prefixes)

    if len(proxies) != 2:
        for received_key in proxies:
            if received_key not in keys:
                raise InvalidPayloadError(f"Unexpected entry in proxy_servers: {received_key}")

    for prefix in key_prefixes:
        value = get_optional_str(proxies, key(prefix))
        if len(value) > 0:
            new_proxy_docker_config['proxies']['default'][docker_key(prefix)] = value

    merge_dictionaries(docker_config_data, new_proxy_docker_config, overwrite_existing_keys=True)
    write_users_docker_config_file(docker_config_data)
    if reload_daemons:
        _client.query(topics.docker.restart, "")


def docker_compose_proxy_del(message: bytes) -> None:
    docker_config_data = read_users_docker_config_file()
    data = json.loads(message)

    for proxy, to_delete in data.items():
        if to_delete:
            # http_proxy -> httpProxy, https_proxy -> httpsProxy
            docker_config_data["proxies"]["default"].pop(proxy.replace("_p", "P"), None)

    write_users_docker_config_file(docker_config_data)
    _client.query(topics.docker.restart, "")


def main() -> None:
    def in_bg(topic: str, fun: com_client.SyncHandlerCallable, post_respond: Optional[Callable[[Any], None]] = None) -> None:
        messages[topic] = background(fun, com_client.respond_to(_client, topic), post_respond=post_respond)

    messages = {}
    messages[topics.docker.compose.get_config] = guarded(sync(docker_compose_get_config))
    in_bg(topics.docker.compose.set_config, guarded(docker_compose_set_config))
    messages[topics.docker.compose.status] = guarded(sync(docker_compose_status))
    in_bg(topics.docker.compose.add, guarded(docker_compose_add))
    messages[topics.docker.compose.get] = guarded(sync(docker_compose_get))
    in_bg(topics.docker.compose.delete, guarded(docker_compose_del))
    in_bg(topics.docker.compose.recreate, guarded(docker_compose_recreate))
    messages[topics.docker.compose.auth_add] = guarded(sync(docker_compose_auth_add))
    messages[topics.docker.compose.auth_remove] = guarded(sync(docker_compose_auth_remove))
    messages[topics.docker.compose.proxy.add] = guarded(sync(docker_compose_proxy_add))
    messages[topics.docker.compose.proxy.delete] = guarded(sync(docker_compose_proxy_del))

    _client.register_responders(messages)

    if _client.has_responding_handler(topics.docker.compose.set_config):
        logger.info('Init compose')
        start_all_compositions()

    while True:
        _client.wait_and_receive()


if __name__ == "__main__":
    main()
