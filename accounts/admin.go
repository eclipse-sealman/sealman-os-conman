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
	"os/user"
)

const (
	DevadminGidString = "5000"
	DevreadGidString  = "5001"
)

type userLookupFunc func(username string) (*user.User, error)

func userInDevadminDevreadGid(username string, lookup userLookupFunc) (bool, error) {
	u, err := lookup(username)
	if err != nil {
		return false, err
	}
	return u.Gid == DevadminGidString || u.Gid == DevreadGidString, nil
}

func UserInDevadminDevreadGid(username string) (bool, error) {
	return userInDevadminDevreadGid(username, user.Lookup)
}
