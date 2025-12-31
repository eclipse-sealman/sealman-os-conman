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
from enum import Enum


class NetlinkEvents(Enum):
    RTM_NEWNEIGH = "RTM_NEWNEIGH"
    RTM_DELNEIGH = "RTM_DELNEIGH"
    RTM_NEWLINK = "RTM_NEWLINK"
    RTM_DELLINK = "RTM_DELLINK"
    RTM_NEWADDR = "RTM_NEWADDR"
    RTM_DELADDR = "RTM_DELADDR"
    RTM_NEWROUTE = "RTM_NEWROUTE"
    RTM_DELROUTE = "RTM_DELROUTE"


# those routes do not require via or dev
GLOBAL_ROUTES = [
    "blackhole",
    "unreachable",
    "throw",
    "prohibit",
]
TYPES = ["nat", "local", "unicast", "broadcast", "multicast"] + GLOBAL_ROUTES
SCOPES = ["link", "host", "global"]
MPA = 200
DEFAULT_VLAN_METRIC = 101
