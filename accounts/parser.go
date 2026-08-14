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
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// SkipFunc decides whether a raw line should be skipped.
type SkipFunc func(line string) bool

// SkipComments skips empty lines and lines starting with '#'.
func SkipComments(line string) bool {
	return len(line) > 0 && line[0] == '#'
}

// SkipEmpty skips only empty lines.
func SkipEmpty(line string) bool {
	return line == ""
}

// SkipAny combines multiple SkipFuncs — skips if any returns true.
func SkipAny(fns ...SkipFunc) SkipFunc {
	return func(line string) bool {
		for _, fn := range fns {
			if fn(line) {
				return true
			}
		}
		return false
	}
}

// ParseLines reads r, splits each line by sep, and applies fn to each line's fields.
// skip determines which raw lines are ignored; use nil to skip nothing.
func ParseLines[T any](r io.Reader, sep string, skip SkipFunc, fn func(fields []string) (T, error)) ([]T, error) {
	var results []T
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if skip != nil && skip(line) {
			continue
		}
		fields := strings.Split(line, sep)
		v, err := fn(fields)
		if err != nil {
			return nil, fmt.Errorf("line %q: %w", line, err)
		}
		results = append(results, v)
	}
	return results, scanner.Err()
}

// ReadLines opens a file and applies ParseLines with the given fn.
func ReadLines[T any](path string, fn func(io.Reader) ([]T, error)) ([]T, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return fn(f)
}
