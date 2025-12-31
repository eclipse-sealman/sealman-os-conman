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
# /etc/eg/tmout.sh shall define TMOUT if needed
if [[ -r /etc/eg/tmout.sh ]] ; then
	. /etc/eg/tmout.sh
	if [[ -v TMOUT ]] ; then
		export TMOUT
	else
		echo Missing TMOUT in /etc/eg/tmout.sh --- please report to Welotec
	fi
fi
