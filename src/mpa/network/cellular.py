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
import sys
from dataclasses import dataclass
from subprocess import CalledProcessError
from typing import Any, Protocol

from mpa.common.logger import Logger
from mpa.communication.process import run_command

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")


class ModemError(RuntimeError):
    ...


@dataclass(frozen=True)
class SignalMetrics:
    rsrp: int | None       # dBm
    rsrq: float | None     # dB
    rssi: int | None       # dBm


@dataclass(frozen=True)
class Sim:
    dbus_path: str
    active: str
    iccid: str
    imsi: str
    operator_code: str
    operator_name: str


@dataclass(frozen=True)
class Modem:
    dbus_path: str
    sim_dbus_path: str
    imei: str
    operator_code: str
    operator_name: str
    registration_state: str
    access_technologies: list[str]
    revision: str
    unlock_required: str
    state_failed_reason: str
    state: str
    ports: list[str]


@dataclass(frozen=True)
class ModemInfo:
    modem: Modem
    sim: Sim | None
    signal_metrics: SignalMetrics | None


class SignalMetricsStrategy(Protocol):
    def get_signal_metrics(self, modem_dbus_path: str) -> SignalMetrics:
        ...


def send_at_command(modem_dbus_path: str, command: str) -> str:
    return run_command(f"mmcli -m {modem_dbus_path} --command='{command}'", timeout=5).stdout.decode()


class QengStrategy:
    def get_signal_metrics(self, modem_dbus_path: str) -> SignalMetrics:
        response = send_at_command(modem_dbus_path, 'AT+QENG="servingcell"')
        return self.parse_qeng(response)

    def parse_qeng(self, response: str) -> SignalMetrics:
        # +QENG: "servingcell","NOCONN","LTE","FDD",262,03,D2201A,481,1600,3,5,5,89CA,-107,-12,-73,...
        # Fields after "FDD": MCC,MNC,cellID,PCID,earfcn,freq_band,UL_bw,DL_bw,TAC (9 fields), then RSRP,RSRQ,RSSI
        for line in response.splitlines():
            if "+QENG:" in line:
                _, data = line.strip().split('+QENG:', 1)
                parts = [p.strip().strip('"') for p in data.strip().split(',')]
                break
        else:
            raise ValueError(f"Cannot parse +QENG response: {response}")

        # parts[0]  = servingcell
        # parts[1]  = state
        # parts[2]  = LTE
        # parts[3]  = FDD/TDD
        # parts[4..12] = MCC,MNC,cellID,PCID,earfcn,freq_band,UL_bw,DL_bw,TAC
        # parts[13] = RSRP
        # parts[14] = RSRQ
        # parts[15] = RSSI
        try:
            return SignalMetrics(rsrp=int(parts[13]), rsrq=float(parts[14]), rssi=int(parts[15]))
        except (ValueError, IndexError) as e:
            raise ValueError(f"Cannot parse +QENG fields: {e}")


class CesqStrategy:
    def get_signal_metrics(self, modem_dbus_path: str) -> SignalMetrics:
        cesq = send_at_command(modem_dbus_path, "AT+CESQ")
        csq = send_at_command(modem_dbus_path, "AT+CSQ")
        return SignalMetrics(
            rsrp=self.parse_rsrp(cesq),
            rsrq=self.parse_rsrq(cesq),
            rssi=self.parse_rssi(csq),
        )

    def parse_rsrp(self, response: str) -> int | None:
        # +CESQ: <rxlev>,<ber>,<rscp>,<ecn0>,<rsrq>,<rsrp>
        parts = self.cesq_parts(response)
        raw = int(parts[5])
        return raw - 141 if raw != 255 else None

    def parse_rsrq(self, response: str) -> float | None:
        parts = self.cesq_parts(response)
        raw = int(parts[4])
        return (raw - 40) / 2 if raw != 255 else None

    def parse_rssi(self, response: str) -> int | None:
        # +CSQ: <rssi>,<ber>  rssi 0..31, 99=unknown → dBm = rssi*2 - 113
        for line in response.splitlines():
            if "+CSQ:" in line:
                _, data = line.strip().split("+CSQ:", 1)
                raw = int(data.strip().split(',')[0].strip())
                return raw * 2 - 113 if raw != 99 else None
        raise ValueError(f"Cannot parse +CSQ response: {response}")

    def cesq_parts(self, response: str) -> list[str]:
        for line in response.splitlines():
            if "+CESQ:" in line:
                _, data = line.strip().split("+CESQ:", 1)
                return [p.strip() for p in data.strip().split(',')]
        raise ValueError(f"Cannot parse +CESQ response: {response}")


def select_signal_metrics_strategy(modem_info: Modem) -> SignalMetricsStrategy:
    strategy_map: list[tuple[str, SignalMetricsStrategy]] = [
        ("EM05", QengStrategy()),
        ("LE910", CesqStrategy()),
        ("LE92", CesqStrategy()),
    ]

    for prefix, strategy in strategy_map:
        if modem_info.revision.startswith(prefix):
            return strategy

    raise ModemError(f"Unknown modem model '{modem_info.revision}'")


def fetch_modem_list() -> list[str]:
    raw = run_command("mmcli -L -J", timeout=5).stdout.decode()
    out = json.loads(raw)
    modem_list: list[str] = out.get("modem-list", [])
    return modem_list


def fetch_modem_data(modem_debus_path: str) -> dict[str, Any]:
    raw = run_command(f"mmcli -m {modem_debus_path} -J", timeout=5).stdout.decode()
    data = json.loads(raw)
    assert isinstance(data, dict)
    return data


def fetch_sim_data(sim_dbus_path: str) -> dict[str, Any]:
    raw = run_command(f"mmcli -i {sim_dbus_path} -J", timeout=5).stdout.decode()
    data = json.loads(raw)
    assert isinstance(data, dict)
    return data


def parse_modem_data(data: dict[str, Any]) -> Modem:
    modem = data["modem"]
    generic = modem["generic"]
    gpp = modem["3gpp"]

    return Modem(
        dbus_path=modem["dbus-path"],
        sim_dbus_path=generic["sim"],
        imei=gpp["imei"],
        operator_code=gpp["operator-code"],
        operator_name=gpp["operator-name"],
        registration_state=gpp["registration-state"],
        access_technologies=generic["access-technologies"],
        revision=generic["revision"],
        unlock_required=generic["unlock-required"],
        state_failed_reason=generic["state-failed-reason"],
        state=generic["state"],
        ports=generic["ports"],
    )


def parse_sim_data(data: dict[str, Any]) -> Sim:
    sim = data["sim"]
    properties = sim["properties"]

    return Sim(
        dbus_path=sim["dbus-path"],
        active=properties["active"],
        iccid=properties["iccid"],
        imsi=properties["imsi"],
        operator_code=properties["operator-code"],
        operator_name=properties["operator-name"],
    )


def find_modem_by_index(index: int) -> Modem:
    try:
        modem_list: list[str] = fetch_modem_list()
    except (json.JSONDecodeError, CalledProcessError) as e:
        raise ModemError(f"Cannot fetch modem list: {e}")

    for modem_path in modem_list:
        try:
            modem_data = fetch_modem_data(modem_path)
        except (json.JSONDecodeError, CalledProcessError) as e:
            logger.warning(f"Cannot fetch modem data for {modem_path}: {e}")
            continue

        try:
            modem_info = parse_modem_data(modem_data)
        except KeyError as e:
            logger.warning(f"Cannot parse modem data for {modem_path}: {e}")
            continue

        for port in modem_info.ports:
            if port.startswith(f"cellular{index}"):
                return modem_info

    raise ModemError(f"Cannot find modem for index: {index}")


def get_modem_info(modem_index: int) -> ModemInfo:
    modem = find_modem_by_index(modem_index)
    strategy = select_signal_metrics_strategy(modem)

    try:
        sim_info = parse_sim_data(fetch_sim_data(modem.sim_dbus_path))
    except (json.JSONDecodeError, CalledProcessError, KeyError) as e:
        logger.warning(f"Cannot fetch or parse SIM data for {modem.sim_dbus_path}: {e}")
        sim_info = None

    try:
        signal_metrics = strategy.get_signal_metrics(modem.dbus_path)
    except (CalledProcessError, ValueError) as e:
        logger.warning(f"Failed to get signal metrics: {e}")
        signal_metrics = None

    return ModemInfo(modem=modem, sim=sim_info, signal_metrics=signal_metrics)
