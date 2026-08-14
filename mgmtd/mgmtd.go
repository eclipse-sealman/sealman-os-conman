// Copyright (c) 2025 Contributors to the Eclipse Foundation.
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License, Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0
package mgmtd

import (
	"net"
	"os"
)

const (
	MgmtdUid = 16580
	MgmtdGid = 16580
)

func CreateMgmtdUnixListener(socketPath string) (net.Listener, error) {
	if _, err := os.Stat(socketPath); err == nil {
		if err := os.Remove(socketPath); err != nil {
			return nil, err
		}
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}

	if err := os.Chown(socketPath, MgmtdUid, MgmtdGid); err != nil {
		return nil, err
	}

	if err := os.Chmod(socketPath, 0600); err != nil {
		return nil, err
	}

	return listener, nil
}
