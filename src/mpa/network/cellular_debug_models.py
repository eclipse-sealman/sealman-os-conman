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

from __future__ import annotations
from dataclasses import dataclass, asdict
import json
from typing import Any, List


@dataclass(frozen=True)
class SignalQuality:
    value: str
    recent: str


@dataclass(frozen=True)
class Generic:
    unlock_required: str
    state: str
    state_failed_reason: str
    access_technologies: List[str]


@dataclass(frozen=True)
class Modem3gpp:
    imei: str
    operator_id: str
    operator_name: str
    registration_state: str


@dataclass(frozen=True)
class SignalMetrics:
    rxlev:   int | None = None
    ber:  int | None = None
    rscp:  int | None = None
    ecno:  int | None = None
    rsrq:  int | None = None
    rsrp:  int | None = None
    rssi: int | None = None


@dataclass(frozen=True)
class Sim:
    iccid: str | None = None
    imsi: str | None = None
    operator_name: str | None = None
    operator_id: str | None = None
    status: str | None = None


@dataclass(frozen=True)
class ModemInfo:
    generic: Generic
    modem3gpp: Modem3gpp | None = None
    signalmetrics: SignalMetrics | None = None
    sim: Sim | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self, dict_factory=lambda x: {k: v for (k, v) in x if v is not None})

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
