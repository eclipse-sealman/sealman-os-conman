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
	"bytes"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// AuthorizedKey represents a single entry in an OpenSSH authorized_keys
// file: a public key together with any leading options (e.g.
// "no-port-forwarding") and a trailing comment.
type AuthorizedKey struct {
	// Options are the comma-separated authorized_keys options that
	// precede the key, if any (e.g. "no-pty", "command=\"...\"").
	Options []string
	// Key is the parsed public key itself.
	Key ssh.PublicKey
	// Comment is the free-text label that follows the key, if any.
	Comment string
}

// String renders the key back into a single authorized_keys line, in the
// same "options key comment" form it would appear in on disk.
func (k *AuthorizedKey) String() string {
	var options string
	if len(k.Options) > 0 {
		options = strings.Join(k.Options, ",") + " "
	}
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k.Key)))
	if k.Comment != "" {
		return fmt.Sprintf("%s%s %s", options, key, k.Comment)
	}
	return options + key
}

// EqualTo reports whether k and another are the same key material.
// Options and comments are ignored: two entries for the same key with
// different options/comments are still considered equal.
func (k *AuthorizedKey) EqualTo(another AuthorizedKey) bool {
	return bytes.Equal(k.Key.Marshal(), another.Key.Marshal())
}

// assertUniqueAuthorizedKeys returns an error if any two entries in keys
// are equal per AuthorizedKey.EqualTo. It returns nil for an empty or
// nil slice.
func assertUniqueAuthorizedKeys(keys []AuthorizedKey) error {
	for i := range len(keys) {
		for j := i + 1; j < len(keys); j++ {
			if keys[i].EqualTo(keys[j]) {
				return fmt.Errorf("key %s and %s are equal", keys[i].String(), keys[j].String())
			}
		}
	}
	return nil
}

// removeAuthorizedKeyByIndex returns a new slice with the entry at idx
// removed, leaving keys itself unmodified. It returns an error if idx is
// out of range.
func removeAuthorizedKeyByIndex(idx int, keys []AuthorizedKey) ([]AuthorizedKey, error) {
	if idx < 0 || idx >= len(keys) {
		return nil, fmt.Errorf("index %d out of range", idx)
	}
	result := make([]AuthorizedKey, 0, len(keys)-1)
	result = append(result, keys[:idx]...)
	result = append(result, keys[idx+1:]...)
	return result, nil
}

// addAuthorizedKey returns keys with key appended, or an error if an
// entry with the same key material (per AuthorizedKey.EqualTo) is
// already present.
func addAuthorizedKey(key AuthorizedKey, keys []AuthorizedKey) ([]AuthorizedKey, error) {
	for _, k := range keys {
		if k.EqualTo(key) {
			return keys, fmt.Errorf("key %s already present in authorized_keys", key.String())
		}
	}
	return append(keys, key), nil
}

// authorizedKeysToStrings renders each key in keys via AuthorizedKey.String,
// preserving order. It returns an empty (non-nil) slice for empty input.
func authorizedKeysToStrings(keys []AuthorizedKey) []string {
	result := make([]string, len(keys))
	for i, key := range keys {
		result[i] = key.String()
	}
	return result
}

// parseAuthorizedKeys parses the contents of an authorized_keys file,
// returning one AuthorizedKey per line. It returns an error on the first
// line it cannot parse.
func parseAuthorizedKeys(data []byte) ([]AuthorizedKey, error) {
	var keys []AuthorizedKey
	for len(data) > 0 {
		key, comment, options, rest, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			return nil, err
		}
		keys = append(keys, AuthorizedKey{options, key, comment})
		data = rest
	}
	return keys, nil
}

// readAuthorizedKeys reads and parses the authorized_keys file at path.
// It returns an error if the file cannot be read or its contents cannot
// be parsed.
func readAuthorizedKeys(path string) ([]AuthorizedKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseAuthorizedKeys(bytes.TrimSpace(data))
}

// writeAuthorizedKeys writes keys to path in authorized_keys format,
// one entry per line, overwriting any existing content. It does not
// create missing parent directories.
func writeAuthorizedKeys(path string, keys []AuthorizedKey) error {
	return os.WriteFile(path, []byte(strings.Join(authorizedKeysToStrings(keys), "\n")+"\n"), 0644)
}
