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
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network

import pytest

from mpa.network.dhcp_server import (
    Dhcp4Config,
    Lease,
    LeaseTimeSeconds,
    LeaseTimeSecondsValueError,
    Subnet4,
    SubnetValueError,
)
from mpa.network.ipv4_address_range import IPv4AddressRange

SAMPLE_CONFIG_DICT = {
    "Dhcp4": {
        "interfaces-config": {
            "interfaces": ["lan1"]
        },
        "subnet4": [{
            "subnet": "192.168.0.0/24",
            "pools": [{"pool": "192.168.0.10-192.168.0.100"}],
            "valid-lifetime": 3600,
            "option-data": [
                {"name": "domain-name-servers", "data": "192.168.0.1, 192.168.0.2"},
                {"name": "routers", "data": "192.168.0.254"},
            ]
        }]
    }
}


@pytest.fixture(scope="module")
def subnet4():
    return Subnet4(
        network=IPv4Network("192.168.0.0/24"),
        ip_range=IPv4AddressRange.from_str("192.168.0.10-192.168.0.100"),
        lease_time=LeaseTimeSeconds(3600),
        dns=[IPv4Address("192.168.0.1"), IPv4Address("192.168.0.2")],
        gateway=IPv4Address("192.168.0.254"),
    )


@pytest.fixture(scope="module")
def subnet4_dict():
    return {
        "network": "192.168.0.0/24",
        "ip_range": "192.168.0.10-192.168.0.100",
        "lease_time": 3600,
        "dns": ["192.168.0.1", "192.168.0.2"],
        "gateway": "192.168.0.254",
    }


@pytest.fixture(scope="module")
def dhcp4_config(subnet4):
    return Dhcp4Config(subnets={"lan1": subnet4})


@pytest.fixture(scope="module")
def dhcp4_config_dict(subnet4_dict):
    return {"lan1": subnet4_dict}


class TestLeaseTimeSeconds:
    def test_lease_time_seconds_valid_value_succeeds(self):
        assert LeaseTimeSeconds(120) == 120

    def test_lease_time_seconds_below_minimum_raises_value_error(self):
        with pytest.raises(LeaseTimeSecondsValueError, match="lease time shorter than one minute"):
            LeaseTimeSeconds(30)

    def test_lease_time_seconds_minimum_value_succeeds(self):
        assert LeaseTimeSeconds(60) == 60


class TestLease:
    def test_lease_to_dict_converts_timestamp_to_isoformat(self):
        lease = Lease(
            ip_address="192.168.0.10",
            hw_address="00:11:22:33:44:55",
            hostname="test_host",
            expire_timestamp=1693545587,
        )
        result = lease.to_dict()
        assert result == {
            "ip_address": "192.168.0.10",
            "hw_address": "00:11:22:33:44:55",
            "hostname": "test_host",
            "expire": datetime.fromtimestamp(1693545587).isoformat(),
        }

    def test_lease_empty_hostname_to_dict(self):
        lease = Lease(
            ip_address="192.168.0.10",
            hw_address="00:11:22:33:44:55",
            hostname="",
            expire_timestamp=1693545587,
        )
        result = lease.to_dict()
        assert result["hostname"] == ""


class TestSubnet4:
    def test_subnet4_invalid_ip_range_not_in_network_raises_value_error(self):
        with pytest.raises(SubnetValueError, match="part '192.168.1.10' of '192.168.1.10-192.168.1.100' not in network '192.168.0.0/24'"):
            Subnet4(
                network=IPv4Network("192.168.0.0/24"),
                ip_range=IPv4AddressRange.from_str("192.168.1.10-192.168.1.100"),
                lease_time=LeaseTimeSeconds(3600),
                dns=[IPv4Address("192.168.0.1")],
                gateway=IPv4Address("192.168.0.254"),
            )

    def test_subnet4_to_dict_converts_to_expected_format(self, subnet4, subnet4_dict):
        assert subnet4.to_dict() == subnet4_dict

    def test_subnet4_from_dict_creates_correct_instance(self, subnet4_dict):
        subnet = Subnet4.from_dict(subnet4_dict)
        assert subnet.network == IPv4Network("192.168.0.0/24")
        assert str(subnet.ip_range) == "192.168.0.10-192.168.0.100"
        assert subnet.lease_time == 3600
        assert subnet.dns == [IPv4Address("192.168.0.1"), IPv4Address("192.168.0.2")]
        assert subnet.gateway == IPv4Address("192.168.0.254")

    def test_subnet4_to_kea_dict_converts_to_expected_format(self, subnet4):
        assert subnet4.to_kea_dict() == SAMPLE_CONFIG_DICT["Dhcp4"]["subnet4"][0]

    def test_subnet4_from_kea_dict_creates_correct_instance(self):
        subnet = Subnet4.from_kea_dict(SAMPLE_CONFIG_DICT["Dhcp4"]["subnet4"][0])
        assert subnet.network == IPv4Network("192.168.0.0/24")
        assert str(subnet.ip_range) == "192.168.0.10-192.168.0.100"
        assert subnet.lease_time == 3600
        assert subnet.dns == [IPv4Address("192.168.0.1"), IPv4Address("192.168.0.2")]
        assert subnet.gateway == IPv4Address("192.168.0.254")

    def test_subnet4_no_dns_no_gateway_to_kea_dict(self):
        subnet = Subnet4(
            network=IPv4Network("192.168.0.0/24"),
            ip_range=IPv4AddressRange.from_str("192.168.0.10-192.168.0.100"),
            lease_time=LeaseTimeSeconds(3600),
        )
        assert subnet.to_kea_dict() == {
            "subnet": "192.168.0.0/24",
            "pools": [{"pool": "192.168.0.10-192.168.0.100"}],
            "valid-lifetime": 3600,
            "option-data": [],
        }


class TestDhcp4Config:
    def test_dhcp4_config_to_dict_converts_to_expected_format(self, dhcp4_config, dhcp4_config_dict):
        assert dhcp4_config.to_dict() == dhcp4_config_dict

    def test_dhcp4_config_to_kea_dict_converts_to_expected_format(self, dhcp4_config):
        assert dhcp4_config.to_kea_dict() == SAMPLE_CONFIG_DICT

    def test_dhcp4_config_from_dict_creates_correct_instance(self, dhcp4_config_dict):
        config = Dhcp4Config.from_dict(dhcp4_config_dict)
        assert len(config.subnets) == 1
        assert config.subnets["lan1"].network == IPv4Network("192.168.0.0/24")
        assert str(config.subnets["lan1"].ip_range) == "192.168.0.10-192.168.0.100"

    def test_dhcp4_config_from_kea_dict_creates_correct_instance(self):
        config = Dhcp4Config.from_kea_dict(SAMPLE_CONFIG_DICT)
        assert len(config.subnets) == 1
        assert config.subnets["lan1"].network == IPv4Network("192.168.0.0/24")
        assert str(config.subnets["lan1"].ip_range) == "192.168.0.10-192.168.0.100"
        assert config.subnets["lan1"].dns == [IPv4Address("192.168.0.1"), IPv4Address("192.168.0.2")]
        assert config.subnets["lan1"].gateway == IPv4Address("192.168.0.254")

    def test_dhcp4_config_empty_subnets_to_dict(self):
        config = Dhcp4Config(subnets={})
        assert config.to_dict() == {}

    def test_dhcp4_config_empty_subnets_to_kea_dict(self):
        config = Dhcp4Config(subnets={})
        assert config.to_kea_dict() == {
            "Dhcp4": {
                "interfaces-config": {"interfaces": []},
                "subnet4": [],
            }
        }
