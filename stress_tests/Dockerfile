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
# Environment for stress tests (see README.md), build context shall be code/:
#   docker build -t mpa-stress-tests -f code/stress_tests/Dockerfile code
#   docker run --rm -v "$PWD/code:/work" mpa-stress-tests
#
FROM ghcr.io/astral-sh/uv:bookworm-slim

RUN apt update && \
    apt install -y --no-install-recommends \
    # forwarder (message_router)
    build-essential \
    libzmq3-dev \
    cppzmq-dev \
    libboost-program-options-dev \
    # python dependencies of mpa (see pyproject.toml)
    git \
    pkg-config \
    python3-dev \
    libsystemd-dev \
    libgirepository1.0-dev \
    gir1.2-nm-1.0 \
    libcairo2-dev \
    libtss2-dev \
    libarchive-dev && \
    apt clean && rm -rf /var/lib/apt/lists/*

ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_PYTHON_INSTALL_DIR=/opt/python \
    UV_CACHE_DIR=/tmp/uv-cache \
    HOME=/tmp \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/work/src \
    MPA_FORWARDER_BUILD_DIR=/tmp/forwarder-build

# Dependencies are installed in image, sources (including mpa itself) come from volume mounted at /work
COPY pyproject.toml uv.lock .python-version /opt/project/
RUN cd /opt/project && uv sync --frozen --all-extras --no-install-project && chmod -R a+rX /opt/venv /opt/python

WORKDIR /work
CMD ["/opt/venv/bin/python", "-m", "pytest", "-p", "no:cacheprovider", "-v", "stress_tests"]
