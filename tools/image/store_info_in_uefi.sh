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
uefi_vars=serial_number=`dmidecode -s system-serial-number`\;model=`hdparm -I /dev/sda|grep "Model Number:"|  awk '{ s = ""; for (i = 3; i <= NF; i++) s = s $i " "; print s }'`\;serial=`hdparm -I /dev/sda | grep "Serial Number" |awk '{print $3}'`\;core_count=`dmidecode --type 4 |grep -i "core count" | awk '{print $3}'`\;processor_version=`dmidecode -s processor-version`\;ram_size=`dmidecode --type 17|grep -i size|awk '{print $2""$3}'`\;disc_size=`hdparm -I /dev/sda|grep "device size"|head -n 1|awk '{print $7"MB"}'`\;product_name=`dmidecode -s system-product-name`\;system_model="to be defined during production"
echo $uefi_vars
chattr -i /sys/firmware/efi/efivars/mpa-f436e81f-c0ff-4072-ab5a-39003aff5b6b 
printf "\x07\x00\x00\x00$uefi_vars" > /sys/firmware/efi/efivars/mpa-f436e81f-c0ff-4072-ab5a-39003aff5b6b
