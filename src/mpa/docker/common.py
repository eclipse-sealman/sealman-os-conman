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
# Standard imports
import shutil
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from pathlib import Path
from typing import Any

# Third party imports
import tenacity

# Local imports
from mpa.communication.process import run_command
from mpa.common.logger import Logger
from mpa.common.common import RESPONSE_OK

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")

COMPOSED_HOME = Path("/home/composed")
COMPOSE_FILES_DIR = COMPOSED_HOME / "containers"


def run_docker_compose(cmd: str, **kwargs: Any) -> None:
    run_command(f"docker compose {cmd}", **kwargs)


def validate_compose_file(compose_dir: Path) -> None:
    """
    Executes docker compose config
    """
    run_docker_compose("config", cwd=compose_dir)


def compose_callback(future: Future[bytes]) -> None:
    logger.info(f"Future ({threading.get_ident()}) has finished: {future.result()=} {future.exception()=}")


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


def validate_and_run_compose(compose_dir: Path, force_recreate: bool = False) -> str:
    try:
        validate_compose_file(compose_dir)
        docker_compose_up(compose_dir, force_recreate=force_recreate)
    except Exception as e:
        logger.error(f"Validation or startup failed for compose '{compose_dir.name}', removing it: {e}")
        shutil.rmtree(compose_dir, ignore_errors=True)
        raise
 
    return RESPONSE_OK
 

def docker_compose_up_async(*compose_dirs: Path, force_recreate: bool = False, timeout: int = 15) -> dict[str, str]:
    """
    Executes multiple docker compose up -d in a thread pool.

    If there are threads downloading given image in the background then calling this function again will not
    duplicate the download - it only happens once. On the other hand the composition process happens in every thread
    and they will race with each other. Only one will succeed and return a successful result (the others will fail with
    the information that a given container already exists).
    """
    if len(compose_dirs) == 0:
        return {}

    exe = ThreadPoolExecutor(max_workers=len(compose_dirs))
    futures = {
        exe.submit(validate_and_run_compose, compose_dir, force_recreate): compose_dir.name for compose_dir in compose_dirs
    }

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
    except TimeoutError:
        for future, name in futures.items():
            if name not in results:
                results[name] = f"{RESPONSE_OK} Composition continues in the background"

    exe.shutdown(wait=False)
    return results
