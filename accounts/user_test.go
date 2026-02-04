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
	"errors"
	"testing"
)

func TestLookupManagedUserByName(t *testing.T) {
	input := []PasswdEntry{
		{Name: "charlie", Gid: DevadminGid},
	}

	user, err := lookupManagedUserByName("charlie", input)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if user.Name != "charlie" {
		t.Errorf("got username %q, want %q", user.Name, "charlie")
	}
}

func TestLookupManagedUserByName_NotInManagedGroup(t *testing.T) {
	input := []PasswdEntry{
		{Name: "root", Uid: 0, Gid: 0},
		{Name: "charlie", Gid: 1000},
	}

	for _, user := range input {
		_, err := lookupManagedUserByName(user.Name, input)

		var got *UserNotInManagedGroupError
		if !errors.As(err, &got) {
			t.Fatalf("expected UserNotInManagedGroupError, got %T: %v", err, err)
		}

		if got.Username != user.Name {
			t.Errorf("got username %q, want %q", got.Username, "charlie")
		}
	}
}

func TestLookupManagedUserByName_NotFound(t *testing.T) {
	input := []PasswdEntry{
		{Name: "alice", Gid: DevadminGid},
	}

	_, err := lookupManagedUserByName("dave", input)

	var got *UserNotFoundError
	if !errors.As(err, &got) {
		t.Fatalf("expected UserNotFoundError, got %T: %v", err, err)
	}

	if got.Username != "dave" {
		t.Errorf("got username %q, want %q", got.Username, "dave")
	}
}

func TestGetAllManagedUsers(t *testing.T) {
	cases := []struct {
		name  string
		input []PasswdEntry
		want  []PasswdEntry
	}{
		{
			name: "devadmin gid",
			input: []PasswdEntry{
				{Name: "alice", Gid: DevadminGid},
				{Name: "bob", Gid: 1000},
			},
			want: []PasswdEntry{{Name: "alice", Gid: DevadminGid}},
		},
		{
			name: "devread gid",
			input: []PasswdEntry{
				{Name: "alice", Gid: DevreadGid},
				{Name: "bob", Gid: 1000},
			},
			want: []PasswdEntry{{Name: "alice", Gid: DevreadGid}},
		},
		{
			name: "no managed users",
			input: []PasswdEntry{
				{Name: "bob", Gid: 1000},
			},
			want: []PasswdEntry{},
		},
		{
			name:  "empty input",
			input: []PasswdEntry{},
			want:  []PasswdEntry{},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := getAllManagedUsers(c.input)
			if len(got) != len(c.want) {
				t.Fatalf("got %d entries, want %d", len(got), len(c.want))
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("entry %d: got %+v, want %+v", i, got[i], c.want[i])
				}
			}
		})
	}
}
