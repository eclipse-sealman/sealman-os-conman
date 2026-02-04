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

import "fmt"

// DevadminGid and DevreadGid are the primary group IDs that mark a system
// user as "managed" by this package. A user is considered managed if and
// only if their primary GID (as read from /etc/passwd) is one of these
// two values; see isUserInManagedGroup.
const (
	DevadminGid = 5000
	DevreadGid  = 5001
)

// UserNotFoundError indicates that no passwd entry exists for Username.
type UserNotFoundError struct {
	Username string
}

func (e *UserNotFoundError) Error() string {
	return fmt.Sprintf("user %s not found", e.Username)
}

// UserNotInManagedGroupError indicates that Username exists but is not a
// member of the devadmin or devread group, and therefore is not eligible
// for operations that require a managed user.
type UserNotInManagedGroupError struct {
	Username string
}

func (e *UserNotInManagedGroupError) Error() string {
	return fmt.Sprintf("user %s is not in devadmin/devread group", e.Username)
}

// filterUsers returns the subset of users for which filter reports true,
// preserving order. It returns an empty (non-nil) slice if no entries
// match.
func filterUsers(users []PasswdEntry, filter func(PasswdEntry) bool) []PasswdEntry {
	filtered := []PasswdEntry{}
	for _, user := range users {
		if filter(user) {
			filtered = append(filtered, user)
		}
	}
	return filtered
}

// lookupUserByName returns the entry in users whose Name matches name.
// It returns a *UserNotFoundError if no such entry exists.
func lookupUserByName(name string, users []PasswdEntry) (PasswdEntry, error) {
	for _, user := range users {
		if user.Name == name {
			return user, nil
		}
	}
	return PasswdEntry{}, &UserNotFoundError{Username: name}
}

// isUserInManagedGroup reports whether user's primary GID is DevadminGid
// or DevreadGid. This is the sole check that defines "managed" for the
// purposes of this package.
func isUserInManagedGroup(user PasswdEntry) bool {
	return user.Gid == DevadminGid || user.Gid == DevreadGid
}

// getAllManagedUsers returns the subset of users that are in the managed
// group, per isUserInManagedGroup.
func getAllManagedUsers(users []PasswdEntry) []PasswdEntry {
	return filterUsers(users, isUserInManagedGroup)
}

// lookupManagedUserByName returns the entry in users named name, but only
// if that user is in the managed group. It returns a *UserNotFoundError
// if no user with that name exists, or a *UserNotInManagedGroupError if
// the user exists but is not managed.
func lookupManagedUserByName(name string, users []PasswdEntry) (PasswdEntry, error) {
	user, err := lookupUserByName(name, users)
	if err != nil {
		return PasswdEntry{}, err
	}
	if !isUserInManagedGroup(user) {
		return PasswdEntry{}, &UserNotInManagedGroupError{Username: name}
	}
	return user, nil
}

// LookupUserByNameFromSystem reads the system's passwd database and
// returns the entry for name, regardless of whether that user is
// managed. It returns a *UserNotFoundError if no such user exists.
func LookupUserByNameFromSystem(name string) (PasswdEntry, error) {
	users, err := ReadPasswd()
	if err != nil {
		return PasswdEntry{}, err
	}
	return lookupUserByName(name, users)
}

// LookupManagedUserByNameFromSystem reads the system's passwd database
// and returns the entry for name, provided that user is a member of the
// managed group (devadmin or devread). It returns a *UserNotFoundError if
// no such user exists, or a *UserNotInManagedGroupError if the user
// exists but isn't managed. This is the sole entry point through which
// callers should resolve a name to a managed user.
func LookupManagedUserByNameFromSystem(name string) (PasswdEntry, error) {
	users, err := ReadPasswd()
	if err != nil {
		return PasswdEntry{}, err
	}
	return lookupManagedUserByName(name, users)
}

// GetAllManagedUsersFromSystem reads the system's passwd database and
// returns every entry whose primary GID is devadmin or devread.
func GetAllManagedUsersFromSystem() ([]PasswdEntry, error) {
	entries, err := ReadPasswd()
	if err != nil {
		return nil, err
	}
	users := getAllManagedUsers(entries)
	return users, nil
}
