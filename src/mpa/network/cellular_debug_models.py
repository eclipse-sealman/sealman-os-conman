from __future__ import annotations
from dataclasses import dataclass, asdict
import json


@dataclass
class SignalQuality:
    value: str
    recent: str


@dataclass
class Generic:
    unlock_required: str
    state: str
    state_failed_reason: str
    access_technologies: list


@dataclass
class Modem3gpp:
    imei: str
    operator_id: str
    operator_name: str
    registration_state: str


@dataclass
class SignalMetrics:
    rxlev:   int | None = None
    ber:  int | None = None
    rscp:  int | None = None
    ecno:  int | None = None
    rsrq:  int | None = None
    rsrp:  int | None = None
    rssi: int | None = None


@dataclass
class Sim:
    iccid: str | None = None
    imsi: str | None = None
    operator_name: str | None = None
    operator_id: str | None = None
    status: str | None = None


@dataclass
class ModemInfo:
    generic: Generic
    modem3gpp: Modem3gpp | None = None
    signalmetrics: SignalMetrics | None = None
    sim: Sim | None = None

    def to_dict(self) -> dict:

        modem_d: dict = {"generic": asdict(self.generic)}
        if self.modem3gpp:
            modem_d["3gpp"] = asdict(self.modem3gpp)
        if self.signalmetrics:
            modem_d["signalmetrics"] = asdict(self.signalmetrics)
        if self.sim:
            modem_d["sim"] = asdict(self.sim)
        return modem_d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
