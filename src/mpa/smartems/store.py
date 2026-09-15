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
import json
import os
from pathlib import Path
from typing import Any, Protocol


class Store(Protocol):
    def load(self) -> Any: ...

    def save(self, data: Any) -> None: ...

    def clear(self) -> None: ...


class DefaultStore:
    def __init__(self, path: Path):
        self._path = path

    def load(self) -> Any:
        if not self._path.exists():
            return None

        return json.loads(self._path.read_text().strip())

    def save(self, data: Any) -> None:
        if len(data) == 0:
            return

        save_count = data.get("save_count", 0)
        data["save_count"] = save_count + 1

        self._path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self._path.with_suffix(".tmp")
        with temp_path.open("w", encoding="utf-8") as file:
            os.fchmod(file.fileno(), 0o600)
            json.dump(data, file, indent=2)
            file.flush()
            os.fsync(file.fileno())

        os.replace(temp_path, self._path)

    def clear(self) -> None:
        self._path.unlink(missing_ok=True)
