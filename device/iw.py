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
import sys

import pyroute2

if __name__ == "__main__":
    with pyroute2.IW() as iw:
        match sys.argv:
            case [_, "set", alpha2]:
                regdom = alpha2.strip()
                iw.set_regulatory_domain(regdom)
            case _:
                print("use set <alpha2>", file=sys.stderr)
                sys.exit(1)
