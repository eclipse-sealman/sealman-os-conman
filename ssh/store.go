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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/eclipse-sealman/sealman-os-conman/accounts"
)

// UserKeyStore operates on the authorized_keys file for a single user.
// It holds no cached state — every method re-reads or re-writes the
// underlying file, so there's nothing here that can go stale.
type UserKeyStore struct {
	user accounts.PasswdEntry
}

// NewUserKeyStore wraps an already-resolved PasswdEntry. Exported so
// tests and other packages that already have a PasswdEntry (e.g. after
// their own lookup) can use it without going through name resolution.
func NewUserKeyStore(user accounts.PasswdEntry) UserKeyStore {
	return UserKeyStore{user: user}
}

// NewManagedUserKeyStore resolves name through the managed-user lookup
// and returns a store scoped to that user. This is the only place the
// "must be a managed user" boundary is enforced.
func NewManagedUserKeyStore(name string) (UserKeyStore, error) {
	user, err := accounts.LookupManagedUserByNameFromSystem(name)
	if err != nil {
		return UserKeyStore{}, err
	}
	return NewUserKeyStore(user), nil
}

func (s UserKeyStore) path() (string, error) {
	fi, err := os.Stat(s.user.Directory)
	if err != nil {
		return "", fmt.Errorf("home directory %q is unavailable: %w", s.user.Directory, err)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("home path %q is not a directory", s.user.Directory)
	}
	path := filepath.Join(s.user.Directory, ".ssh/authorized_keys")
	_, err = os.Stat(path)
	return path, err
}

func (s UserKeyStore) pathWritable() (string, error) {
	path, err := s.path()
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	sshDir := filepath.Dir(path)
	if err := os.MkdirAll(sshDir, 0744); err != nil {
		return "", fmt.Errorf("create ssh dir for user %s: %w", s.user.Name, err)
	}
	if err := os.Chown(sshDir, s.user.Uid, s.user.Gid); err != nil {
		return "", fmt.Errorf("chown ssh dir for user %s: %w", s.user.Name, err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		if os.IsExist(err) {
			return path, nil
		}
		return "", fmt.Errorf("create authorized_keys for user %s: %w", s.user.Name, err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close authorized_keys for user %s: %w", s.user.Name, err)
	}
	if err := os.Chown(path, s.user.Uid, s.user.Gid); err != nil {
		return "", fmt.Errorf("chown authorized_keys for user %s: %w", s.user.Name, err)
	}
	return path, nil
}

func (s UserKeyStore) write(keys []AuthorizedKey) error {
	p, err := s.pathWritable()
	if err != nil {
		return err
	}
	return writeAuthorizedKeys(p, keys)
}

// List returns the user's current authorized keys as AuthorizedKey values.
func (s UserKeyStore) List() ([]AuthorizedKey, error) {
	p, err := s.path()
	if err != nil && os.IsNotExist(err) {
		return []AuthorizedKey{}, nil
	}
	if err != nil {
		return nil, err
	}
	return readAuthorizedKeys(p)
}

// ListStrings returns the user's current authorized keys as formatted lines.
func (s UserKeyStore) ListStrings() ([]string, error) {
	keys, err := s.List()
	if err != nil {
		return nil, err
	}
	return authorizedKeysToStrings(keys), nil
}

// Add appends a single new key, rejecting it if it's a duplicate of one
// already present.
func (s UserKeyStore) Add(rawKey string) error {
	newKeys, err := parseAuthorizedKeys([]byte(rawKey))
	if err != nil {
		return err
	}
	if len(newKeys) != 1 {
		return fmt.Errorf("expected one authorized key, got: %d", len(newKeys))
	}
	keys, err := s.List()
	if err != nil {
		return err
	}
	keys, err = addAuthorizedKey(newKeys[0], keys)
	if err != nil {
		return err
	}
	return s.write(keys)
}

// Remove deletes the key at idx (as returned by List).
func (s UserKeyStore) Remove(idx int) error {
	keys, err := s.List()
	if err != nil {
		return err
	}
	updated, err := removeAuthorizedKeyByIndex(idx, keys)
	if err != nil {
		return err
	}
	return s.write(updated)
}

// Replace overwrites the entire authorized_keys file with rawKeys,
// rejecting the set if it contains duplicates.
func (s UserKeyStore) Replace(rawKeys []string) error {
	keys, err := parseAuthorizedKeys([]byte(strings.Join(rawKeys, "\n")))
	if err != nil {
		return err
	}
	if err := assertUniqueAuthorizedKeys(keys); err != nil {
		return err
	}
	return s.write(keys)
}
