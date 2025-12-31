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
# Standard imports
from enum import Enum

# GENERAL SYSTEM CODES
SUCCESS = 0
FAILURE = 1
YES = 'y'
NO = 'n'

# USER CONFIG
ADD_USER = 'add'
REMOVE_USER = 'remove'
SHOW_USERS = 'list'
ADMIN_GROUP = 'admin'
USER_GROUP = 'user'
ADMIN_SYSTEM_GROUP = 'devadmin'
USER_SYSTEM_GROUP = 'devread'
DEVADMIN_GID = 5000
DEVREAD_GID = 5001

# Firewall config
FIREWALL_PROTOCOLS = ["ip", "ip6", "tcp", "udp", "sctp", "icmp", "icmpv6"]

# DEVICE CONFIG
REMOVE_EVERYTHING = 'everything'

# LOGROTATE
HOUR = 'hourly'
DAY = 'daily'
WEEK = 'weekly'
MONTH = 'monthly'


class CERTIFICATE(Enum):
    ADD = "add"
    DELETE = "delete"
    SHOW = "show"
