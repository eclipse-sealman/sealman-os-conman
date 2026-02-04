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

package accounts

import (
	"testing"
)

func passwdEntryEq(a, b PasswdEntry) bool {
	return a.Name == b.Name &&
		a.Password == b.Password &&
		a.Uid == b.Uid &&
		a.Gid == b.Gid &&
		a.Gecos == b.Gecos &&
		a.Directory == b.Directory &&
		a.Shell == b.Shell
}

func TestParsePasswdEntry(t *testing.T) {
	cases := []struct {
		name    string
		fields  []string
		want    PasswdEntry
		wantErr bool
	}{
		{
			name:   "valid full entry",
			fields: []string{"root", "x", "0", "0", "root", "/root", "/bin/bash"},
			want: PasswdEntry{
				Name:      "root",
				Password:  "x",
				Uid:       0,
				Gid:       0,
				Gecos:     "root",
				Directory: "/root",
				Shell:     "/bin/bash",
			},
		},
		{
			name:   "valid regular user",
			fields: []string{"alice", "x", "1000", "1000", "Alice Smith", "/home/alice", "/bin/sh"},
			want: PasswdEntry{
				Name:      "alice",
				Password:  "x",
				Uid:       1000,
				Gid:       1000,
				Gecos:     "Alice Smith",
				Directory: "/home/alice",
				Shell:     "/bin/sh",
			},
		},
		{name: "too few fields", fields: []string{"root", "x", "0"}, wantErr: true},
		{name: "invalid Uid", fields: []string{"root", "x", "bad", "0", "", "/root", "/bin/bash"}, wantErr: true},
		{name: "invalid Gid", fields: []string{"root", "x", "0", "bad", "", "/root", "/bin/bash"}, wantErr: true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parsePasswdEntry(c.fields)
			if (err != nil) != c.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, c.wantErr)
			}
			if !c.wantErr && !passwdEntryEq(got, c.want) {
				t.Errorf("got %+v, want %+v", got, c.want)
			}
		})
	}
}
