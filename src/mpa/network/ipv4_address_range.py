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
import re
from typing import NamedTuple
from ipaddress import AddressValueError, IPv4Address


class IPv4AddressRangeValueError(ValueError):
    """Raised when an invalid IP address range is provided."""


class IPv4AddressRange(NamedTuple):
    """A NamedTuple representing a range of IPv4 addresses.

    Attributes:
        lower_bound (IPv4Address): The lower bound of the IP address range.
        upper_bound (IPv4Address): The upper bound of the IP address range.
    """

    lower_bound: IPv4Address
    upper_bound: IPv4Address

    @classmethod
    def from_str(cls, address_range: str) -> IPv4AddressRange:
        """Creates an IPv4AddressRange from a string in the format '<ip_addr>-<ip_addr>'.

        Args:
            address_range (str): A string representing the IP address range, e.g., '192.168.1.1-192.168.1.100'.

        Returns:
            IPv4AddressRange: An instance of IPv4AddressRange with validated lower and upper bounds.

        Raises:
            IPv4AddressRangeValueError: If the address range format is invalid, contains invalid IP addresses,
                or represents a decreasing range (lower_bound > upper_bound).
        """
        _match = re.match(r"(\d+\.){3}\d+-(\d+\.){3}\d+", address_range)
        if _match is None:
            raise IPv4AddressRangeValueError(
                f"invalid IP address range '{address_range}', format is '<ip_addr>-<ip_addr>'"
            )

        try:
            left, right = address_range.split("-")
            lower_bound, upper_bound = IPv4Address(left), IPv4Address(right)
        except AddressValueError as e:
            raise IPv4AddressRangeValueError(f"invalid IP address in range '{address_range}': {e}")

        if lower_bound > upper_bound:
            raise IPv4AddressRangeValueError(f"decreasing IP range '{address_range}'")

        return cls(lower_bound, upper_bound)

    def __str__(self) -> str:
        """Returns a string representation of the IP address range.

        Returns:
            str: The range in the format '<lower_bound>-<upper_bound>', e.g., '192.168.1.1-192.168.1.100'.
        """
        return f"{self.lower_bound}-{self.upper_bound}"
