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
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"
)

var authorizedKeysComment = []string{
	"# This file is managed by mgmtd-ssh and is regenerated on every change.",
	"# On write comment lines and lines that are not valid authorized_keys",
	"# entries are removed automatically and this header is added.",
}



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

// parseAuthorizedKey expects single line, returns parsed key or error on
// comments and invalid keys.
func parseAuthorizedKey(rawKey string) (AuthorizedKey, error) {
	rawKey = strings.TrimSpace(rawKey)
	if len(rawKey) == 0 || rawKey[0] == '#' {
		return AuthorizedKey{}, errors.New("no key found")
	}
	key, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(rawKey))
	if err != nil {
		return AuthorizedKey{}, err
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return AuthorizedKey{}, errors.New("expected exactly one authorized_keys entry")
	}
	return AuthorizedKey{Options: options, Key: key, Comment: comment}, nil
}

// parseAuthorizedKeyList parses entries supplied by user/socket, one entry
// per element. We expect only keys via this route, so parsing is strict.
func parseAuthorizedKeyList(rawKeyList []string) ([]AuthorizedKey, error) {
	keys := make([]AuthorizedKey, 0, len(rawKeyList))
	for i, rawKey := range rawKeyList {
		key, err := parseAuthorizedKey(rawKey)
		if err != nil {
			return nil, fmt.Errorf("key %d (%q): %w", i, rawKey, err)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// parseAuthorizedKeysFile ignores things like ssh --- side effect is that we
// drop comments and invalid keys silently
func parseAuthorizedKeysFileContent(fileContent []byte) []AuthorizedKey {
	var keys []AuthorizedKey
	for _, line := range strings.Split(string(fileContent), "\n") {
		if key, err := parseAuthorizedKey(line); err == nil {
			keys = append(keys, key)
		}
	}
	return keys
}

func readAuthorizedKeys(path string) ([]AuthorizedKey, error) {
	// We don't expect this file to be huge ever, and reading it as a whole
	// into memory simplifies code
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseAuthorizedKeysFileContent(data), nil
}

// writeAuthorizedKeys writes keys to path in authorized_keys format,
// one entry per line, overwriting any existing content. It does not
// create missing parent directories.
func writeAuthorizedKeys(path string, keys []AuthorizedKey) error {
	lines := append(slices.Clone(authorizedKeysComment), authorizedKeysToStrings(keys)...)
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}
