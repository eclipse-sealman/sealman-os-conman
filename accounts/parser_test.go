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
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func TestSkipEmpty(t *testing.T) {
	if !SkipEmpty("") {
		t.Error("expected empty string to be skipped")
	}
	if SkipEmpty("hello") {
		t.Error("expected non-empty string to not be skipped")
	}
}

func TestSkipComments(t *testing.T) {
	if !SkipComments("#comment") {
		t.Error("expected comment line to be skipped")
	}
	if SkipComments("hello") {
		t.Error("expected non-comment line to not be skipped")
	}
}

func TestSkipAny(t *testing.T) {
	skip := SkipAny(SkipEmpty, SkipComments)
	cases := []struct {
		line string
		want bool
	}{
		{"", true},
		{"#comment", true},
		{"hello", false},
	}
	for _, c := range cases {
		if got := skip(c.line); got != c.want {
			t.Errorf("SkipAny(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

func TestParseLines(t *testing.T) {
	input := "a:b:c\n#comment and then empty line\n    \nd:e:f\n"
	results, err := ParseLines(strings.NewReader(input), ":", SkipAny(SkipEmpty, SkipComments), func(f []string) ([]string, error) {
		return f, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0][0] != "a" || results[1][0] != "d" {
		t.Errorf("unexpected results: %v", results)
	}
}

func TestParseLines_FnError(t *testing.T) {
	input := "a:b\n"
	_, err := ParseLines(strings.NewReader(input), ":", nil, func(f []string) ([]string, error) {
		return nil, errors.New("parse error")
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "parse error") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestReadLines_FileNotFound(t *testing.T) {
	_, err := ReadLines("/nonexistent/file", func(r io.Reader) ([][]string, error) {
		return ParseLines(r, ":", nil, func(f []string) ([]string, error) {
			return f, nil
		})
	})
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestReadLines_ValidFile(t *testing.T) {
	content := "x:y:z\na:b:c\n"
	f := t.TempDir() + "/test.txt"
	if err := os.WriteFile(f, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	results, err := ReadLines(f, func(r io.Reader) ([][]string, error) {
		return ParseLines(r, ":", nil, func(fields []string) ([]string, error) {
			return fields, nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
}
