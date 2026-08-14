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

func intPtr(v int) *int { return &v }

func intPtrEq(a, b *int) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func TestOptInt(t *testing.T) {
	cases := []struct {
		input   string
		want    *int
		wantErr bool
	}{
		{"", nil, false},
		{"42", intPtr(42), false},
		{"notanint", nil, true},
	}
	for _, c := range cases {
		v, err := optInt(c.input)
		if (err != nil) != c.wantErr {
			t.Errorf("optInt(%q) error = %v, wantErr %v", c.input, err, c.wantErr)
		}
		if !c.wantErr && !intPtrEq(v, c.want) {
			t.Errorf("optInt(%q) = %v, want %v", c.input, v, c.want)
		}
	}
}

func shadowEntryEq(a, b ShadowEntry) bool {
	return a.Name == b.Name &&
		a.Hash == b.Hash &&
		intPtrEq(a.LastChange, b.LastChange) &&
		intPtrEq(a.MinDays, b.MinDays) &&
		intPtrEq(a.MaxDays, b.MaxDays) &&
		intPtrEq(a.WarnDays, b.WarnDays) &&
		intPtrEq(a.Inactive, b.Inactive) &&
		intPtrEq(a.Expire, b.Expire)
}

func TestParseShadowEntry(t *testing.T) {
	cases := []struct {
		name    string
		fields  []string
		want    ShadowEntry
		wantErr bool
	}{
		{
			name:   "valid full entry",
			fields: []string{"root", "$6$hash", "19000", "0", "99999", "7", "30", "20000", ""},
			want: ShadowEntry{
				Name:       "root",
				Hash:       "$6$hash",
				LastChange: intPtr(19000),
				MinDays:    intPtr(0),
				MaxDays:    intPtr(99999),
				WarnDays:   intPtr(7),
				Inactive:   intPtr(30),
				Expire:     intPtr(20000),
			},
		},
		{
			name:   "valid empty optional fields",
			fields: []string{"user", "*", "", "", "", "", "", "", ""},
			want:   ShadowEntry{Name: "user", Hash: "*"},
		},
		{name: "too few fields", fields: []string{"root", "hash", "1"}, wantErr: true},
		{name: "invalid LastChange", fields: []string{"root", "hash", "bad", "0", "99999", "7", "", "", ""}, wantErr: true},
		{name: "invalid MinDays", fields: []string{"root", "hash", "100", "bad", "99999", "7", "", "", ""}, wantErr: true},
		{name: "invalid MaxDays", fields: []string{"root", "hash", "100", "0", "bad", "7", "", "", ""}, wantErr: true},
		{name: "invalid WarnDays", fields: []string{"root", "hash", "100", "0", "99999", "bad", "", "", ""}, wantErr: true},
		{name: "invalid Inactive", fields: []string{"root", "hash", "100", "0", "99999", "7", "bad", "", ""}, wantErr: true},
		{name: "invalid Expire", fields: []string{"root", "hash", "100", "0", "99999", "7", "", "bad", ""}, wantErr: true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseShadowEntry(c.fields)
			if (err != nil) != c.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, c.wantErr)
			}
			if !c.wantErr && !shadowEntryEq(got, c.want) {
				t.Errorf("got %+v, want %+v", got, c.want)
			}
		})
	}
}
