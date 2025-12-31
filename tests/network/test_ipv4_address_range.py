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
import pytest

from mpa.network.ipv4_address_range import (
    IPv4AddressRange,
    IPv4AddressRangeValueError,
)


def test_ipv4_address_range_valid_range_parsing_and_string_representation():
    ip_range = IPv4AddressRange.from_str("192.168.0.1-192.168.0.255")
    assert str(ip_range) == "192.168.0.1-192.168.0.255"
    assert str(ip_range.lower_bound) == "192.168.0.1"
    assert str(ip_range.upper_bound) == "192.168.0.255"


def test_ipv4_address_range_invalid_order_raises_value_error():
    with pytest.raises(IPv4AddressRangeValueError):
        IPv4AddressRange.from_str("192.168.0.255-192.168.0.1")


def test_ipv4_address_range_invalid_format_missing_octet_raises_value_error():
    with pytest.raises(IPv4AddressRangeValueError):
        IPv4AddressRange.from_str("192.168.0.1-192.168.0")


def test_ipv4_address_range_single_ip_address():
    ip_range = IPv4AddressRange.from_str("192.168.0.1-192.168.0.1")
    assert str(ip_range) == "192.168.0.1-192.168.0.1"
    assert str(ip_range.lower_bound) == "192.168.0.1"
    assert str(ip_range.upper_bound) == "192.168.0.1"


def test_ipv4_address_range_invalid_ip_address_raises_value_error():
    with pytest.raises(IPv4AddressRangeValueError):
        IPv4AddressRange.from_str("256.168.0.1-192.168.0.255")


def test_ipv4_address_range_non_ip_string_raises_value_error():
    with pytest.raises(IPv4AddressRangeValueError):
        IPv4AddressRange.from_str("not.an.ip.address-192.168.0.255")


def test_ipv4_address_range_empty_string_raises_value_error():
    with pytest.raises(IPv4AddressRangeValueError):
        IPv4AddressRange.from_str("")


def test_ipv4_address_range_missing_range_delimiter_raises_value_error():
    with pytest.raises(IPv4AddressRangeValueError):
        IPv4AddressRange.from_str("192.168.0.1")


def test_ipv4_address_range_boundary_values():
    ip_range = IPv4AddressRange.from_str("0.0.0.0-255.255.255.255")
    assert str(ip_range) == "0.0.0.0-255.255.255.255"
    assert str(ip_range.lower_bound) == "0.0.0.0"
    assert str(ip_range.upper_bound) == "255.255.255.255"
