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
package nm

import (
	"github.com/godbus/dbus/v5"
)

const activeConnectionInterface = "org.freedesktop.NetworkManager.Connection.Active"

// https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.Connection.Active.html
type ActiveConnection struct {
	conn *dbus.Conn
	obj  dbus.BusObject
}

func NewActiveConnection(conn *dbus.Conn, path dbus.ObjectPath) *ActiveConnection {
	return &ActiveConnection{conn: conn, obj: conn.Object(NMService, path)}
}

func (a *ActiveConnection) Id() (string, error) {
	return getPropertyValue[string](a.obj, activeConnectionInterface+".Id")
}
