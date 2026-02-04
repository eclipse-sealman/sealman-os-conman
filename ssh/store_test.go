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

	"github.com/eclipse-sealman/sealman-os-conman/accounts"
)

// tempUser returns a PasswdEntry backed by a fresh temp directory, usable
// as a real (writable, ownable-by-the-test-process) home directory.
func tempUser(t *testing.T) accounts.PasswdEntry {
	t.Helper()

	return accounts.PasswdEntry{
		Name:      "testuser",
		Uid:       os.Getuid(),
		Gid:       os.Getgid(),
		Directory: t.TempDir(),
	}
}

// tempStore returns a UserKeyStore backed by a fresh temp-dir user, along
// with the underlying PasswdEntry in case a test needs direct access to it.
func tempStore(t *testing.T) (UserKeyStore, accounts.PasswdEntry) {
	t.Helper()

	user := tempUser(t)
	return NewUserKeyStore(user), user
}

func TestNewManagedUserKeyStore(t *testing.T) {
	// LookupManagedUserByNameFromSystem depends on the real system's
	// passwd/group state, which isn't controllable from a unit test.
	// We only assert that a lookup failure (e.g. an unknown name) is
	// propagated rather than swallowed.
	if _, err := NewManagedUserKeyStore("no-such-managed-user-xyz"); err == nil {
		t.Error("expected error for unknown/unmanaged user name")
	}
}

func TestUserKeyStorePath(t *testing.T) {
	t.Run("missing home directory", func(t *testing.T) {
		store := NewUserKeyStore(accounts.PasswdEntry{Name: "testuser"})
		if _, err := store.path(); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("missing authorized keys file", func(t *testing.T) {
		store, user := tempStore(t)
		path, err := store.path()
		if !os.IsNotExist(err) {
			t.Fatalf("error = %v, want os.ErrNotExist", err)
		}
		if path != filepath.Join(user.Directory, ".ssh", "authorized_keys") {
			t.Errorf("path = %q", path)
		}
	})

	t.Run("home path is not a directory", func(t *testing.T) {
		dir := t.TempDir()
		filePath := filepath.Join(dir, "not-a-dir")
		if err := os.WriteFile(filePath, []byte("x"), 0644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}
		store := NewUserKeyStore(accounts.PasswdEntry{
			Name:      "testuser",
			Uid:       os.Getuid(),
			Gid:       os.Getgid(),
			Directory: filePath,
		})
		if _, err := store.path(); err == nil {
			t.Error("expected error when home path is not a directory")
		}
	})

	t.Run("existing authorized keys file", func(t *testing.T) {
		store, user := tempStore(t)
		sshDir := filepath.Join(user.Directory, ".ssh")
		if err := os.MkdirAll(sshDir, 0755); err != nil {
			t.Fatalf("failed to create .ssh dir: %v", err)
		}
		keysPath := filepath.Join(sshDir, "authorized_keys")
		if err := os.WriteFile(keysPath, []byte(keyWithOptionsAndComment), 0644); err != nil {
			t.Fatalf("failed to write authorized_keys: %v", err)
		}
		path, err := store.path()
		if err != nil {
			t.Fatalf("path() failed: %v", err)
		}
		if path != keysPath {
			t.Errorf("path = %q, want %q", path, keysPath)
		}
	})
}

func TestUserKeyStorePathWritable(t *testing.T) {
	store, _ := tempStore(t)
	path, err := store.pathWritable()
	if err != nil {
		t.Fatalf("pathWritable() failed: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat authorized_keys: %v", err)
	}
	if info.IsDir() {
		t.Fatal("authorized_keys is a directory")
	}
}

func TestUserKeyStorePathWritableIdempotent(t *testing.T) {
	store, _ := tempStore(t)

	firstPath, err := store.pathWritable()
	if err != nil {
		t.Fatalf("first call to pathWritable() failed: %v", err)
	}

	// Write some content so we can confirm the second call doesn't truncate it.
	if err := os.WriteFile(firstPath, []byte(keyWithOptionsAndComment), 0644); err != nil {
		t.Fatalf("failed to seed authorized_keys content: %v", err)
	}

	secondPath, err := store.pathWritable()
	if err != nil {
		t.Fatalf("second call to pathWritable() failed: %v", err)
	}
	if firstPath != secondPath {
		t.Errorf("paths differ between calls: %q vs %q", firstPath, secondPath)
	}

	data, err := os.ReadFile(secondPath)
	if err != nil {
		t.Fatalf("failed to read authorized_keys: %v", err)
	}
	if string(data) != keyWithOptionsAndComment {
		t.Errorf("existing content was overwritten: got %q", string(data))
	}
}

func TestUserKeyStoreList(t *testing.T) {
	t.Run("no file yet", func(t *testing.T) {
		store, _ := tempStore(t)
		keys, err := store.List()
		if err != nil {
			t.Fatalf("List() failed: %v", err)
		}
		if len(keys) != 0 {
			t.Errorf("got %d keys, want 0", len(keys))
		}
	})

	t.Run("with existing keys", func(t *testing.T) {
		store, _ := tempStore(t)
		if err := store.Add(keyWithOptionsAndComment); err != nil {
			t.Fatalf("Add() failed: %v", err)
		}
		keys, err := store.List()
		if err != nil {
			t.Fatalf("List() failed: %v", err)
		}
		if len(keys) != 1 {
			t.Fatalf("got %d keys, want 1", len(keys))
		}
	})

	t.Run("malformed file", func(t *testing.T) {
		store, user := tempStore(t)
		sshDir := filepath.Join(user.Directory, ".ssh")
		if err := os.MkdirAll(sshDir, 0755); err != nil {
			t.Fatalf("failed to create .ssh dir: %v", err)
		}
		keysPath := filepath.Join(sshDir, "authorized_keys")
		if err := os.WriteFile(keysPath, []byte(malformedKeyLine), 0644); err != nil {
			t.Fatalf("failed to write malformed authorized_keys: %v", err)
		}
		if _, err := store.List(); err == nil {
			t.Error("expected error reading malformed authorized_keys file")
		}
	})

	t.Run("missing home directory", func(t *testing.T) {
		store := NewUserKeyStore(accounts.PasswdEntry{Name: "testuser"})
		if _, err := store.List(); err == nil {
			t.Error("expected error when home directory is missing")
		}
	})
}

func TestUserKeyStoreListStrings(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		store, _ := tempStore(t)
		if err := store.Add(keyWithOptionsAndComment); err != nil {
			t.Fatalf("Add() failed: %v", err)
		}
		got, err := store.ListStrings()
		if err != nil {
			t.Fatalf("ListStrings() failed: %v", err)
		}
		if len(got) != 1 || got[0] != keyWithOptionsAndComment {
			t.Errorf("got %v, want [%q]", got, keyWithOptionsAndComment)
		}
	})

	t.Run("propagates List errors", func(t *testing.T) {
		store := NewUserKeyStore(accounts.PasswdEntry{Name: "testuser"})
		if _, err := store.ListStrings(); err == nil {
			t.Error("expected error when home directory is missing")
		}
	})
}

func TestUserKeyStoreAdd(t *testing.T) {
	t.Run("expects exactly one key", func(t *testing.T) {
		store, _ := tempStore(t)
		twoKeys := keyWithOptionsAndComment + "\n" + keyWithComment
		if err := store.Add(twoKeys); err == nil {
			t.Fatal("expected one authorized key error")
		}
	})

	t.Run("rejects malformed key", func(t *testing.T) {
		store, _ := tempStore(t)
		if err := store.Add(malformedKeyLine); err == nil {
			t.Fatal("expected error adding malformed key")
		}
	})

	t.Run("success", func(t *testing.T) {
		store, _ := tempStore(t)

		if err := store.Add(keyWithOptionsAndComment); err != nil {
			t.Fatalf("Add() failed: %v", err)
		}

		keys, err := store.List()
		if err != nil {
			t.Fatalf("List() failed: %v", err)
		}
		if len(keys) != 1 {
			t.Fatalf("got %d keys, want 1", len(keys))
		}
		if keys[0].String() != keyWithOptionsAndComment {
			t.Errorf("got %q, want %q", keys[0].String(), keyWithOptionsAndComment)
		}

		// Adding a second, distinct key should append rather than overwrite.
		if err := store.Add(keyWithOptions); err != nil {
			t.Fatalf("Add() second call failed: %v", err)
		}
		keys, err = store.List()
		if err != nil {
			t.Fatalf("List() failed: %v", err)
		}
		if len(keys) != 2 {
			t.Fatalf("got %d keys, want 2", len(keys))
		}

		// Re-adding the same key should fail and leave the file unchanged.
		if err := store.Add(keyWithOptionsAndComment); err == nil {
			t.Error("expected error re-adding duplicate key")
		}
		keys, err = store.List()
		if err != nil {
			t.Fatalf("List() failed: %v", err)
		}
		if len(keys) != 2 {
			t.Fatalf("got %d keys after duplicate add attempt, want 2", len(keys))
		}
	})

	t.Run("propagates lookup errors", func(t *testing.T) {
		store := NewUserKeyStore(accounts.PasswdEntry{Name: "testuser"})
		if err := store.Add(keyWithOptionsAndComment); err == nil {
			t.Error("expected error when home directory is missing")
		}
	})
}

func TestUserKeyStoreRemove(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		store, _ := tempStore(t)
		if err := store.Add(keyWithOptionsAndComment); err != nil {
			t.Fatalf("Add() failed: %v", err)
		}
		if err := store.Add(keyWithOptions); err != nil {
			t.Fatalf("Add() failed: %v", err)
		}

		if err := store.Remove(0); err != nil {
			t.Fatalf("Remove() failed: %v", err)
		}

		keys, err := store.List()
		if err != nil {
			t.Fatalf("List() failed: %v", err)
		}
		if len(keys) != 1 {
			t.Fatalf("got %d keys, want 1", len(keys))
		}
		if keys[0].String() != keyWithOptions {
			t.Errorf("got %q, want %q", keys[0].String(), keyWithOptions)
		}
	})

	t.Run("index out of range", func(t *testing.T) {
		store, _ := tempStore(t)
		if err := store.Add(keyWithOptionsAndComment); err != nil {
			t.Fatalf("Add() failed: %v", err)
		}
		if err := store.Remove(5); err == nil {
			t.Error("expected error for out-of-range index")
		}
	})

	t.Run("negative index", func(t *testing.T) {
		store, _ := tempStore(t)
		if err := store.Add(keyWithOptionsAndComment); err != nil {
			t.Fatalf("Add() failed: %v", err)
		}
		if err := store.Remove(-1); err == nil {
			t.Error("expected error for negative index")
		}
	})

	t.Run("propagates lookup errors", func(t *testing.T) {
		store := NewUserKeyStore(accounts.PasswdEntry{Name: "testuser"})
		if err := store.Remove(0); err == nil {
			t.Error("expected error when home directory is missing")
		}
	})
}

func TestUserKeyStoreReplace(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		store, _ := tempStore(t)
		if err := store.Add(keyWithComment); err != nil {
			t.Fatalf("Add() failed: %v", err)
		}

		if err := store.Replace([]string{keyWithOptionsAndComment, keyWithOptions}); err != nil {
			t.Fatalf("Replace() failed: %v", err)
		}

		keys, err := store.List()
		if err != nil {
			t.Fatalf("List() failed: %v", err)
		}
		if len(keys) != 2 {
			t.Fatalf("got %d keys, want 2", len(keys))
		}
	})

	t.Run("rejects duplicates", func(t *testing.T) {
		store, _ := tempStore(t)
		if err := store.Replace([]string{keyWithOptionsAndComment, keyWithComment}); err == nil {
			t.Error("expected error for duplicate keys in replacement set")
		}
	})

	t.Run("rejects malformed input", func(t *testing.T) {
		store, _ := tempStore(t)
		if err := store.Replace([]string{malformedKeyLine}); err == nil {
			t.Error("expected error for malformed replacement key")
		}
	})

	t.Run("empty list clears keys", func(t *testing.T) {
		store, _ := tempStore(t)
		if err := store.Add(keyWithOptionsAndComment); err != nil {
			t.Fatalf("Add() failed: %v", err)
		}
		if err := store.Replace(nil); err != nil {
			t.Fatalf("Replace() failed: %v", err)
		}
		keys, err := store.List()
		if err != nil {
			t.Fatalf("List() failed: %v", err)
		}
		if len(keys) != 0 {
			t.Errorf("got %d keys, want 0", len(keys))
		}
	})
}
