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
	"os"
	"slices"

	"github.com/eclipse-sealman/sealman-os-conman/jsonsocket"
	"github.com/eclipse-sealman/sealman-os-conman/mgmtd"
)

var allowedFiles = []string{"/proc/sys/vm/overcommit_memory"}

type WriteReq struct {
	Flag string `json:"flag"`
	File string `json:"file"`
}

func write(r WriteReq) {
	if r.Flag == "" || r.File == "" {
		panic("empty flag or file")
	}
	if !slices.Contains(allowedFiles, r.File) {
		panic(fmt.Sprintf("file %v not in allowed files", r.File))
	}
	if err := os.WriteFile(r.File, []byte(r.Flag), os.FileMode(0644)); err != nil {
		panic(err)
	}
}

func main() {
	listener, err := mgmtd.CreateMgmtdUnixListener("/run/mgmtd/kernel_daemon")
	if err != nil {
		log.Fatalf("failed to create an mgmtd listener: %v", err)
	}

	jsonsocket.Handle("write", write)

	if err := jsonsocket.ListenAndServe(listener); err != nil {
		log.Fatal(err)
	}
}
