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

package main

import (
	"fmt"
	"log"

	"github.com/eclipse-sealman/sealman-os-conman/accounts"
	"github.com/eclipse-sealman/sealman-os-conman/jsonsocket"
	"github.com/eclipse-sealman/sealman-os-conman/mgmtd"
	"github.com/eclipse-sealman/sealman-os-conman/ssh"
)

type AddReq struct {
	Username string `json:"username"`
	Key      string `json:"key"`
}

func add(r AddReq) {
	store, err := ssh.NewManagedUserKeyStore(r.Username)
	if err != nil {
		panic(err)
	}
	if err := store.Add(r.Key); err != nil {
		panic(err)
	}
}

type RemoveReq struct {
	Username string `json:"username"`
	Idx      int    `json:"idx"`
}

func remove(r RemoveReq) {
	store, err := ssh.NewManagedUserKeyStore(r.Username)
	if err != nil {
		panic(err)
	}
	if err := store.Remove(r.Idx); err != nil {
		panic(err)
	}
}

type ShowReq struct {
	Username string `json:"username"`
}

type ShowResp struct {
	Keys map[string][]string `json:"keys"`
}

func show(r ShowReq) ShowResp {
	store, err := ssh.NewManagedUserKeyStore(r.Username)
	if err != nil {
		panic(err)
	}
	keys, err := store.ListStrings()
	return ShowResp{map[string][]string{r.Username: keys}}
}

type GetAllResp struct {
	Keys       map[string][]string `json:"keys"`
	UserStatus map[string]string   `json:"user_status"`
}

func getAll() GetAllResp {
	keys := make(map[string][]string)
	status := make(map[string]string)
	users, err := accounts.GetAllManagedUsersFromSystem()
	if err != nil {
		panic(err)
	}
	for _, user := range users {
		store := ssh.NewUserKeyStore(user)
		userKeys, err := store.ListStrings()
		if err != nil {
			status[user.Name] = fmt.Sprintf("FAILED: issue with authorized_keys file: %s", err.Error())
			continue
		}
		keys[user.Name] = userKeys
		status[user.Name] = "OK"
	}

	return GetAllResp{Keys: keys, UserStatus: status}
}

type SetAllReq struct {
	Data map[string][]string `json:"data"`
}

type SetAllResp struct {
	UserStatus map[string]string `json:"user_status"`
}

func setAll(r SetAllReq) SetAllResp {
	resp := SetAllResp{UserStatus: make(map[string]string)}
	for username, keys := range r.Data {
		store, err := ssh.NewManagedUserKeyStore(username)
		if err != nil {
			resp.UserStatus[username] = fmt.Sprintf("FAILED: %s", err.Error())
			continue
		}

		if err := store.Replace(keys); err != nil {
			resp.UserStatus[username] = fmt.Sprintf("FAILED: %s", err.Error())
		} else {
			resp.UserStatus[username] = "OK"
		}
	}
	return resp
}

func main() {
	listener, err := mgmtd.CreateMgmtdUnixListener("/run/mgmtd/ssh_daemon")
	if err != nil {
		log.Fatalf("failed to create an mgmtd listener: %v", err)
	}

	jsonsocket.Handle("add", add)
	jsonsocket.Handle("show", show)
	jsonsocket.Handle("remove", remove)
	jsonsocket.Handle("get_all", getAll)
	jsonsocket.Handle("set_all", setAll)

	if err := jsonsocket.ListenAndServe(listener); err != nil {
		log.Fatal(err)
	}
}
