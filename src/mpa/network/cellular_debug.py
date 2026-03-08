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
from gi.repository import Gio, GLib  # type: ignore
from mpa.network.cellular_debug_models import ModemInfo, Generic, Modem3gpp, SignalMetrics, Sim
from mpa.network.cellular_debug_dbus import get_all, find_objects_by_interface, send_at, _MM_IFACE, _MM_SIM_IFACE
from mpa.network.cellular_debug_enums import (
    MODEM_STATE, MODEM_STATE_FAILED_REASON, MODEM_LOCK,
    MODEM_ACCESS_TECHNOLOGY, MODEM_3GPP_REGISTRATION_STATE,
    enum_str,
)
from mpa.common.logger import Logger
import sys
import re
from typing import Any, Dict, Optional

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")


def _build_generic(object_path: str, g: Dict[str, Any]) -> Generic:
    return Generic(
        unlock_required=enum_str(g.get("UnlockRequired", 0), MODEM_LOCK),
        state=enum_str(g.get("State", 0), MODEM_STATE),
        state_failed_reason=enum_str(g.get("StateFailedReason", 0), MODEM_STATE_FAILED_REASON),
        access_technologies=[enum_str(g.get("AccessTechnologies", 0), MODEM_ACCESS_TECHNOLOGY)],
    )


def _build_3gpp(gpp: Dict[str, Any]) -> Modem3gpp | None:
    if not gpp:
        return None
    return Modem3gpp(
        imei=gpp.get("Imei", "--"),
        operator_id=gpp.get("OperatorCode", "--") or "--",
        operator_name=gpp.get("OperatorName", "--") or "--",
        registration_state=enum_str(gpp.get("RegistrationState", 0),
                                    MODEM_3GPP_REGISTRATION_STATE),
    )


def __sim_status(unlock_required: int) -> str:
    if unlock_required == 1:
        return "active, ready"
    else:
        return f"active, {MODEM_LOCK.get(unlock_required)} locked"


def _build_sim(sim: Dict[str, Any], modem_data: Dict[str, Any]) -> Sim | None:
    if not sim:
        return None
    return Sim(
        iccid=sim.get("SimIdentifier", "--"),
        imsi=sim.get("Imsi", "--"),
        operator_name=sim.get("OperatorName", "--"),
        operator_id=sim.get("OperatorIdentifier", "--"),
        status=__sim_status(modem_data.get("UnlockRequired", 0))
    )


def _build_signal_metrics(cesq: str, csq: str) -> SignalMetrics:
    match = re.search(r"\+CESQ:\s*([0-9,]+)", cesq)
    if not match:
        raise ValueError("Invalid +CESQ response")

    parts = match.group(1).split(",")

    if len(parts) != 6:
        raise ValueError("Expected 6 values in +CESQ response")

    cesq_values = list(map(int, parts))

    match = re.search(r"\+CSQ:\s*(\d+),(\d+)", csq)

    if not match:
        raise ValueError("Invalid +CSQ response")
    rssi_raw = int(match.group(1))

    def normalize(value: int) -> Optional[int]:
        if value in (99, 255):
            return None
        # TODO value between 99 and 255 shall never occur, consider using below assert or some logging in case it happens
        #assert value < 100
        return value

    return SignalMetrics(
        rxlev=normalize(cesq_values[0]),
        ber=normalize(cesq_values[1]),
        rscp=normalize(cesq_values[2]),
        ecno=normalize(cesq_values[3]),
        rsrq=normalize(cesq_values[4]),
        rsrp=normalize(cesq_values[5]),
        rssi=normalize(rssi_raw)
    )


def get_modem_info(modem_index: int) -> ModemInfo | None:
    modem_interface_name = f"cellular{modem_index}"
    connection = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
    object_path = find_objects_by_interface(connection, modem_interface_name)
    if object_path:
        try:
            modem_data = get_all(connection, object_path, _MM_IFACE)
        except GLib.Error:
            raise RuntimeError("Modem did not response for basic query")
        try:
            gpp = get_all(connection, object_path, f"{_MM_IFACE}.Modem3gpp")
        except GLib.Error:
            gpp = {}
        try:
            active_sim_path = str(modem_data.get("Sim", ""))
            sim = get_all(connection, active_sim_path, _MM_SIM_IFACE)
        except GLib.Error:
            sim = {}

        cesq = send_at(connection, object_path, "+CESQ")
        csq = send_at(connection, object_path, "+CSQ")
        return ModemInfo(
                generic=_build_generic(object_path, modem_data),
                modem3gpp=_build_3gpp(gpp),
                signalmetrics=_build_signal_metrics(cesq, csq),
                sim=_build_sim(sim, modem_data)
            )
    else:
        return None
