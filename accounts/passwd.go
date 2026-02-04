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
	"fmt"
	"io"
	"strconv"
)

const passwdFile = "/etc/passwd"

type PasswdEntry struct {
	Name      string
	Password  string
	Uid       int
	Gid       int
	Gecos     string
	Directory string
	Shell     string
}

func parsePasswdEntry(f []string) (PasswdEntry, error) {
	if len(f) < 7 {
		return PasswdEntry{}, fmt.Errorf("expected 7 fields, got %d", len(f))
	}

	uid, err := strconv.Atoi(f[2])
	if err != nil {
		return PasswdEntry{}, fmt.Errorf("invalid Uid: %w", err)
	}
	gid, err := strconv.Atoi(f[3])
	if err != nil {
		return PasswdEntry{}, fmt.Errorf("invalid Gid: %w", err)
	}

	return PasswdEntry{
		Name:      f[0],
		Password:  f[1],
		Uid:       uid,
		Gid:       gid,
		Gecos:     f[4],
		Directory: f[5],
		Shell:     f[6],
	}, nil
}

func parsePasswd(r io.Reader) ([]PasswdEntry, error) {
	return ParseLines(r, ":", SkipAny(SkipComments, SkipEmpty), parsePasswdEntry)
}

func ReadPasswd() ([]PasswdEntry, error) {
	return ReadLines(passwdFile, parsePasswd)
}
