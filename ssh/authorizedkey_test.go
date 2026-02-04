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

package ssh

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Test keys generated for testing purposes only.
// Shared across this file and store_test.go.
const (
	keyWithOptionsAndComment    = "from=\"10.0.0.0/8\",no-port-forwarding,no-agent-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGqBMkRpRGVHkHsLhYuqBaDzq1JHYxDt7Gnx3WnQfkiL key-with-options-and-comment"
	keyWithOptions              = "restrict,command=\"echo hello\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBrLRhxFSNpH/4LOWkZT3T2KL/W0Qv7UwZFQUBf4Jrmo"
	keyWithComment              = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGqBMkRpRGVHkHsLhYuqBaDzq1JHYxDt7Gnx3WnQfkiL key-with-comment"
	keyWithoutOptionsAndComment = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGqBMkRpRGVHkHsLhYuqBaDzq1JHYxDt7Gnx3WnQfkiL"
	malformedKeyLine            = "this-is-not-a-valid-ssh-key"
)

// parseTestKey is shared across this file and store_test.go.
func parseTestKey(t *testing.T, raw string) AuthorizedKey {
	t.Helper()

	key, comment, options, _, err := ssh.ParseAuthorizedKey([]byte(raw))
	if err != nil {
		t.Fatalf("failed to parse test key: %v", err)
	}

	return AuthorizedKey{
		Options: options,
		Key:     key,
		Comment: comment,
	}
}

func TestAuthorizedKeyParseAndString(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "options and comment",
			raw:  keyWithOptionsAndComment,
		},
		{
			name: "options",
			raw:  keyWithOptions,
		},
		{
			name: "comment",
			raw:  keyWithComment,
		},
		{
			name: "without options and comment",
			raw:  keyWithoutOptionsAndComment,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys, err := parseAuthorizedKeys([]byte(tt.raw))
			if err != nil {
				t.Fatalf("parseAuthorizedKey() failed: %s", err.Error())
			}
			if len(keys) != 1 {
				t.Errorf("got %d keys, want 1", len(keys))
			}
			key := keys[0]
			if got := key.String(); got != tt.raw {
				t.Errorf("String() = %q, want %q", got, tt.raw)
			}
		})
	}
}

func TestAuthorizedKeyEqualTo(t *testing.T) {
	k1 := parseTestKey(t, keyWithOptionsAndComment)
	k2 := parseTestKey(t, keyWithOptions)
	k1Copy := parseTestKey(t, keyWithOptionsAndComment)

	if !k1.EqualTo(k1Copy) {
		t.Error("expected identical keys to be equal")
	}
	if k1.EqualTo(k2) {
		t.Error("expected different keys to not be equal")
	}

	// Options and comments do not affect key equality.
	k1Copy.Options = []string{"no-pty"}
	k1Copy.Comment = "different comment"
	if !k1.EqualTo(k1Copy) {
		t.Error("expected key equality to ignore options and comments")
	}
}

func TestAssertUniqueAuthorizedKeys(t *testing.T) {
	t.Run("unique keys", func(t *testing.T) {
		k1 := parseTestKey(t, keyWithOptionsAndComment)
		k2 := parseTestKey(t, keyWithOptions)
		if err := assertUniqueAuthorizedKeys([]AuthorizedKey{k1, k2}); err != nil {
			t.Errorf("expected no error for unique keys, got: %v", err)
		}
	})

	t.Run("empty list", func(t *testing.T) {
		if err := assertUniqueAuthorizedKeys(nil); err != nil {
			t.Errorf("expected no error for empty list, got: %v", err)
		}
	})

	t.Run("duplicate keys", func(t *testing.T) {
		k1 := parseTestKey(t, keyWithOptionsAndComment)
		// Same underlying key material, different comment - still a duplicate.
		k1Dup := parseTestKey(t, keyWithComment)
		if err := assertUniqueAuthorizedKeys([]AuthorizedKey{k1, k1Dup}); err == nil {
			t.Error("expected error for duplicate keys")
		}
	})
}

func TestRemoveKeyByIndex(t *testing.T) {
	k1 := parseTestKey(t, keyWithOptionsAndComment)
	k2 := parseTestKey(t, keyWithOptions)
	keys := []AuthorizedKey{k1, k2}

	tests := []struct {
		name    string
		idx     int
		wantLen int
		wantErr bool
	}{
		{name: "remove first", idx: 0, wantLen: 1},
		{name: "remove last", idx: 1, wantLen: 1},
		{name: "negative index", idx: -1, wantErr: true},
		{name: "out of bounds", idx: 2, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := removeAuthorizedKeyByIndex(tt.idx, keys)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr = %v", err, tt.wantErr)
			}
			if !tt.wantErr && len(result) != tt.wantLen {
				t.Errorf("got %d keys, want %d", len(result), tt.wantLen)
			}
		})
	}
}

func TestRemoveKeyByIndexDoesNotMutateInput(t *testing.T) {
	k1 := parseTestKey(t, keyWithOptionsAndComment)
	k2 := parseTestKey(t, keyWithOptions)
	k3 := parseTestKey(t, keyWithComment)
	original := []AuthorizedKey{k1, k2, k3}

	// Copy so we can compare original against itself after the call, since
	// we're specifically testing that it wasn't changed in place.
	before := make([]AuthorizedKey, len(original))
	copy(before, original)

	result, err := removeAuthorizedKeyByIndex(0, original)
	if err != nil {
		t.Fatalf("removeAuthorizedKeyByIndex() failed: %v", err)
	}

	for i := range original {
		if !original[i].EqualTo(before[i]) {
			t.Fatalf("input slice was mutated at index %d: got %s, want %s", i, original[i].String(), before[i].String())
		}
	}

	if len(result) != 2 || !result[0].EqualTo(k2) || !result[1].EqualTo(k3) {
		t.Errorf("unexpected result: %v", authorizedKeysToStrings(result))
	}
}

func TestAddKey(t *testing.T) {
	k1 := parseTestKey(t, keyWithOptionsAndComment)
	k2 := parseTestKey(t, keyWithOptions)

	keys, err := addAuthorizedKey(k1, nil)
	if err != nil {
		t.Fatalf("addKey() failed: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	keys, err = addAuthorizedKey(k2, keys)
	if err != nil {
		t.Fatalf("addKey() failed: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(keys))
	}
}

func TestAddKeyRejectsDuplicate(t *testing.T) {
	k1 := parseTestKey(t, keyWithOptionsAndComment)
	keys, err := addAuthorizedKey(k1, nil)
	if err != nil {
		t.Fatalf("addKey() failed: %v", err)
	}
	if _, err = addAuthorizedKey(k1, keys); err == nil {
		t.Fatal("expected duplicate-key error")
	}
}

func TestConvertKeysToStrings(t *testing.T) {
	keys := []AuthorizedKey{
		parseTestKey(t, keyWithOptionsAndComment),
		parseTestKey(t, keyWithOptions),
	}
	result := authorizedKeysToStrings(keys)
	if len(result) != len(keys) {
		t.Fatalf("got %d strings, want %d", len(result), len(keys))
	}
	for i, key := range keys {
		if result[i] != key.String() {
			t.Errorf("result[%d] = %q, want %q", i, result[i], key.String())
		}
	}
}

func TestConvertKeysToStringsEmpty(t *testing.T) {
	result := authorizedKeysToStrings(nil)
	if len(result) != 0 {
		t.Errorf("got %d strings, want 0", len(result))
	}
}

func TestParseAuthorizedKeysError(t *testing.T) {
	if _, err := parseAuthorizedKeys([]byte(malformedKeyLine)); err == nil {
		t.Error("expected error parsing malformed key data")
	}
}

func TestParseAuthorizedKeysEmpty(t *testing.T) {
	keys, err := parseAuthorizedKeys(nil)
	if err != nil {
		t.Fatalf("parseAuthorizedKeys() failed on empty input: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("got %d keys, want 0", len(keys))
	}
}

func TestReadWriteAuthorizedKeys(t *testing.T) {
	k1 := parseTestKey(t, keyWithOptionsAndComment)
	k2 := parseTestKey(t, keyWithOptions)
	path := filepath.Join(t.TempDir(), "authorized_keys")

	if err := writeAuthorizedKeys(path, []AuthorizedKey{k1, k2}); err != nil {
		t.Fatalf("writeAuthorizedKeys() failed: %v", err)
	}
	keys, err := readAuthorizedKeys(path)
	if err != nil {
		t.Fatalf("readAuthorizedKeys() failed: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(keys))
	}
}

func TestReadAuthorizedKeysErrors(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "does-not-exist")
		if _, err := readAuthorizedKeys(path); err == nil {
			t.Error("expected error reading missing file")
		}
	})

	t.Run("malformed contents", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "authorized_keys")
		if err := os.WriteFile(path, []byte(malformedKeyLine), 0644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}
		if _, err := readAuthorizedKeys(path); err == nil {
			t.Error("expected error reading malformed authorized_keys file")
		}
	})
}

func TestWriteAuthorizedKeysError(t *testing.T) {
	// Parent directory does not exist, so the write should fail.
	path := filepath.Join(t.TempDir(), "no-such-dir", "authorized_keys")
	k1 := parseTestKey(t, keyWithOptionsAndComment)
	if err := writeAuthorizedKeys(path, []AuthorizedKey{k1}); err == nil {
		t.Error("expected error writing to nonexistent directory")
	}
}
