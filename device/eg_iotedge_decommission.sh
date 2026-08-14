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
# Used to decommission the device from IoT Hub
# TODO
# This is a temporary solution, this logic will be moved to specific daemon
# as soon as we will create a deamon running as root that will be able to delete files/directories

iotedge system stop

rm -rf /var/secrets/aziot

for directory in "certd" "keyd" "identityd" "edged" "tpmd"; do
    rm -rf /var/lib/aziot/$directory/*
done

echo "hostname = \"`hostname`\"" > /etc/aziot/config.toml

find /etc/aziot -name 00-super.toml | xargs rm

rm /etc/eg/azure_config_validated
rm /etc/eg/certs/iotedge/*
rm /etc/eg/certs/iotedge_dps_x509/*

iotedge system restart
