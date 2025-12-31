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

# Standard imports
import csv
import json
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Any, ClassVar

# Local imports
from .ipv4_address_range import IPv4AddressRange
from .kea_control_socket_client import KeaControlSocketClient


class LeaseTimeSecondsValueError(ValueError):
    ...


class SubnetValueError(ValueError):
    ...


class LeaseTimeSeconds(int):
    def __new__(cls, t: int) -> LeaseTimeSeconds:
        if t < 60:
            raise LeaseTimeSecondsValueError("lease time shorter than one minute")

        return super().__new__(cls, t)


@dataclass(frozen=True)
class Lease:
    ip_address: str
    hw_address: str
    hostname: str
    expire_timestamp: int

    def to_dict(self) -> dict[str, str | int]:
        lease = self.__dict__.copy()
        lease["expire"] = datetime.fromtimestamp(self.expire_timestamp).isoformat()
        lease.pop("expire_timestamp")
        return lease


@dataclass(frozen=True)
class Subnet4:
    network: IPv4Network
    ip_range: IPv4AddressRange
    lease_time: LeaseTimeSeconds = LeaseTimeSeconds(3600)
    dns: list[IPv4Address] = field(default_factory=list)
    gateway: IPv4Address | None = None

    def __post_init__(self) -> None:
        for bound in (self.ip_range.lower_bound, self.ip_range.upper_bound):
            if bound not in self.network:
                raise SubnetValueError(f"part '{bound}' of '{self.ip_range}' not in network '{self.network}'")

    def to_dict(self) -> dict[str, Any]:
        _dict = self.__dict__.copy()
        _dict["network"] = str(self.network)
        _dict["ip_range"] = str(self.ip_range)
        _dict["lease_time"] = int(self.lease_time)
        _dict["dns"] = [str(d) for d in self.dns]
        _dict["gateway"] = str(self.gateway) if self.gateway is not None else None
        return _dict

    @classmethod
    def from_dict(cls, _dict: dict[str, Any]) -> Subnet4:
        return cls(
            IPv4Network(_dict["network"]),
            IPv4AddressRange.from_str(_dict["ip_range"]),
            LeaseTimeSeconds(_dict["lease_time"]),
            [IPv4Address(d) for d in _dict["dns"]],
            IPv4Address(_dict["gateway"]) if _dict["gateway"] is not None else None,
        )

    def to_kea_dict(self) -> dict[str, Any]:
        kea_dict = {
            "subnet": str(self.network),
            "pools": [{"pool": str(self.ip_range)}],
            "valid-lifetime": self.lease_time,
            "option-data": [],
        }
        assert isinstance(kea_dict["option-data"], list)
        if len(self.dns) > 0:
            kea_dict["option-data"].append({
                "name": "domain-name-servers",
                "data": ", ".join(str(d) for d in self.dns),
            })
        if self.gateway is not None:
            kea_dict["option-data"].append({
                "name": "routers",
                "data": str(self.gateway),
            })
        return kea_dict

    @classmethod
    def from_kea_dict(cls, kea_dict: dict[str, Any]) -> Subnet4:
        network = IPv4Network(kea_dict["subnet"])
        kea_pools = kea_dict["pools"]
        assert len(kea_pools) == 1
        ip_range = IPv4AddressRange.from_str(kea_pools[0]["pool"])
        lease_time = LeaseTimeSeconds(kea_dict["valid-lifetime"])
        option_data = kea_dict["option-data"]
        dns = [
            IPv4Address(d)
            for option in option_data
            for d in option["data"].split(", ")
            if option["name"] == "domain-name-servers"
        ]
        gateway = next((IPv4Address(option["data"]) for option in option_data if option["name"] == "routers"), None)
        return Subnet4(network, ip_range, lease_time, dns, gateway)


@dataclass(frozen=True)
class Dhcp4Config:
    subnets: dict[str, Subnet4]

    def to_dict(self) -> dict[str, Any]:
        return {interface: subnet.to_dict() for interface, subnet in sorted(self.subnets.items())}

    @classmethod
    def from_dict(cls, _dict: dict[str, Any]) -> Dhcp4Config:
        return cls(
            {interface: Subnet4.from_dict(subnet) for interface, subnet in sorted(_dict.items())},
        )

    def to_kea_dict(self) -> dict[str, Any]:
        interfaces = sorted(self.subnets.keys())
        subnets = [self.subnets[interface].to_kea_dict() for interface in interfaces]
        kea_dict: dict[str, Any] = {
            "Dhcp4": {
                "interfaces-config": {
                    "interfaces": interfaces,
                },
                "subnet4": subnets,
            }
        }
        return kea_dict

    @classmethod
    def from_kea_dict(cls, kea_dict: dict[str, Any]) -> Dhcp4Config:
        interfaces = kea_dict["Dhcp4"]["interfaces-config"]["interfaces"]
        subnets = [Subnet4.from_kea_dict(d) for d in kea_dict["Dhcp4"]["subnet4"]]
        assert len(interfaces) == len(subnets)
        return cls(dict(zip(interfaces, subnets)))


class Dhcp4Server:
    EG_CONFIG_PATH: ClassVar[Path] = Path("/etc/kea/dhcp4.json")
    KEA_CONFIG_PATH: ClassVar[Path] = Path("/etc/kea/kea-dhcp4.conf")

    def get_leases(self) -> list[Lease]:
        try:
            with open("/etc/kea/dhcp4.leases") as file:
                reader = csv.DictReader(file)
                return [Lease(line["address"], line["hwaddr"], line["hostname"], int(line["expire"])) for line in reader]

        except FileNotFoundError:
            ...

        return []

    def set_config(self, config: dict[str, Any]) -> None:
        new_kea_config = Dhcp4Config.from_dict(
            {interface: subnet for interface, subnet in config.items() if subnet["enabled"]}
        ).to_kea_dict()
        kea_config = {"Dhcp4": KeaControlSocketClient().config_get()["arguments"]["Dhcp4"]}
        kea_config["Dhcp4"]["interfaces-config"] = new_kea_config["Dhcp4"]["interfaces-config"]
        kea_config["Dhcp4"]["subnet4"] = new_kea_config["Dhcp4"]["subnet4"]

        response = KeaControlSocketClient().config_test(kea_config)
        if response["result"] != 0:
            raise RuntimeError(response["text"])
        response = KeaControlSocketClient().config_set(kea_config)
        if response["result"] != 0:
            raise RuntimeError(response["text"])
        KeaControlSocketClient().config_write(str(self.KEA_CONFIG_PATH))
        if response["result"] != 0:
            raise RuntimeError(response["text"])
        self.EG_CONFIG_PATH.write_text(json.dumps(config))

    def get_config(self) -> dict[str, Any]:
        eg_config = self.get_eg_config()
        kea_config = Dhcp4Config.from_kea_dict(KeaControlSocketClient().config_get()["arguments"])
        for interface, settings in eg_config.items():
            settings["enabled"] = interface in kea_config.subnets
            settings.pop("network", None)

        return eg_config

    def get_eg_config(self) -> dict[str, Any]:
        """Use in case Kea socket is not available (exceptional scenario)"""
        eg_config = json.loads(self.EG_CONFIG_PATH.read_text())
        assert isinstance(eg_config, dict)
        return eg_config
