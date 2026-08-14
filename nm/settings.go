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
	"fmt"

	"github.com/godbus/dbus/v5"
)

const (
	SettingsInterface = "org.freedesktop.NetworkManager.Settings"
	SettingsPath      = "/org/freedesktop/NetworkManager/Settings"
)

// https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.Settings.html
type Settings struct {
	conn *dbus.Conn
	obj  dbus.BusObject
}

func NewSettings(conn *dbus.Conn) *Settings {
	return &Settings{conn: conn, obj: conn.Object(NMService, SettingsPath)}
}

func (s *Settings) Connections() ([]*ConnectionProfile, error) {
	paths, err := getPropertyValue[[]dbus.ObjectPath](s.obj, SettingsInterface+".Connections")
	if err != nil {
		return nil, err
	}

	result := make([]*ConnectionProfile, 0, len(paths))
	for _, p := range paths {
		result = append(result, NewConnectionProfile(s.conn, p))
	}

	return result, nil
}

func (s *Settings) AddConnection(settings map[string]map[string]dbus.Variant) (*ConnectionProfile, error) {
	var path dbus.ObjectPath

	call := s.obj.Call(SettingsInterface+".AddConnection", 0, settings)
	if call.Err != nil {
		return nil, fmt.Errorf("AddConnection failed: %w", call.Err)
	}

	if err := call.Store(&path); err != nil {
		return nil, err
	}

	return NewConnectionProfile(s.conn, path), nil
}

func (s *Settings) FindConnectionById(id string) (*ConnectionProfile, error) {
	conns, err := s.Connections()
	if err != nil {
		return nil, err
	}

	for _, c := range conns {
		cid, err := c.Id()
		if err == nil && cid == id {
			return c, nil
		}
	}

	return nil, nil
}
