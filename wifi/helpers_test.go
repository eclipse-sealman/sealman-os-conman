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
package wifi

import (
	"strings"
	"testing"
)

func TestValidWPAPSK(t *testing.T) {
	tests := []struct {
		name string
		psk  string
		want bool
	}{
		{
			name: "too short",
			psk:  "1234567",
			want: false,
		},
		{
			name: "minimum length passphrase",
			psk:  "12345678",
			want: true,
		},
		{
			name: "normal passphrase",
			psk:  "correcthorsebatterystaple",
			want: true,
		},
		{
			name: "maximum length passphrase",
			psk:  strings.Repeat("a", 63),
			want: true,
		},
		{
			name: "64 char non-hex string",
			psk:  strings.Repeat("g", 64),
			want: false,
		},
		{
			name: "64 char lowercase hex",
			psk:  strings.Repeat("a", 64),
			want: true,
		},
		{
			name: "64 char uppercase hex",
			psk:  strings.Repeat("A", 64),
			want: true,
		},
		{
			name: "64 char mixed hex",
			psk:  "0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF",
			want: true,
		},
		{
			name: "65 char string",
			psk:  strings.Repeat("a", 65),
			want: false,
		},
		{
			name: "empty string",
			psk:  "",
			want: false,
		},
		{
			name: "64 char string with one invalid hex character",
			psk:  strings.Repeat("a", 63) + "z",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validWPAPSK(tt.psk)
			if got != tt.want {
				t.Fatalf("validWPAPSK(%q) = %v, want %v", tt.psk, got, tt.want)
			}
		})
	}
}
