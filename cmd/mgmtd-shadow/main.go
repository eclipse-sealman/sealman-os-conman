package main

import (
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/eclipse-sealman/sealman-os-conman/accounts"
	"github.com/eclipse-sealman/sealman-os-conman/jsonsocket"
	"github.com/eclipse-sealman/sealman-os-conman/mgmtd"
)

type UserPasswordHashes struct {
	Hashes map[string]string `json:"user_password_hashes"`
}

func show() UserPasswordHashes {
	shadowEntries, err := accounts.ReadShadow()
	if err != nil {
		panic(err)
	}

	hashes := make(map[string]string)
	for _, shadowEntry := range shadowEntries {
		if ok, _ := accounts.UserInDevadminDevreadGid(shadowEntry.Name); ok {
			hashes[shadowEntry.Name] = shadowEntry.Hash
		}
	}

	return UserPasswordHashes{hashes}
}

func setConfig(r UserPasswordHashes) {
	var chpasswdInput strings.Builder

	for username, hash := range r.Hashes {
		ok, err := accounts.UserInDevadminDevreadGid(username)
		if err != nil {
			panic(err)
		}

		if !ok {
			panic(fmt.Errorf("cannot change password of %v", username))
		}

		if strings.Contains(hash, "\n") {
			panic("hash contains newline")
		}

		if strings.Contains(hash, ":") {
			panic("hash contains colon")
		}

		fmt.Fprintf(&chpasswdInput, "%s:%s\n", username, hash)
	}

	if chpasswdInput.String() == "" {
		return
	}

	cmd := exec.Command("chpasswd", "-e")
	cmd.Stdin = strings.NewReader(chpasswdInput.String())
	output, err := cmd.CombinedOutput()
	if err != nil {
		panic(fmt.Errorf("chpasswd failed: %s", output))
	}
}

func main() {
	listener, err := mgmtd.CreateMgmtdUnixListener("/run/mgmtd/shadow_daemon")
	if err != nil {
		log.Fatalf("failed to create an mgmtd listener: %v", err)
	}

	jsonsocket.Handle("show", show)
	jsonsocket.Handle("set_config", setConfig)

	if err := jsonsocket.ListenAndServe(listener); err != nil {
		log.Fatal(err)
	}
}
