#!/bin/bash
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
# Remove empty key files from Azure IoT Identity Service key store
# and restart related services so IoT Edge can recover cleanly.

KEY_DIRS="/var/lib/aziot/keyd/keys /var/lib/aziot/certd/certs/"

for KEY_DIR in $KEY_DIRS; do
    if [[ -d "$KEY_DIR" ]]; then
        # Delete zero-byte key files
        find "$KEY_DIR" -type f -size 0 -print |xargs rm -rf
    fi
done
echo "Aziot empty key files removed (if any) and services restarted."

