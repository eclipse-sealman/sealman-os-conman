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
package nm

import (
	"errors"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
)

func TestCastVariant_Success(t *testing.T) {
	v := dbus.MakeVariant("hello")

	val, err := castVariant[string](v, "testProp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if val != "hello" {
		t.Fatalf("expected 'hello', got %v", val)
	}
}

func TestCastVariant_TypeMismatch(t *testing.T) {
	v := dbus.MakeVariant(42)

	_, err := castVariant[string](v, "testProp")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "unexpected type") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestGetVariantValue_Success(t *testing.T) {
	m := map[string]dbus.Variant{
		"key": dbus.MakeVariant(123),
	}

	val, err := getVariantValue[int](m, "key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if val != 123 {
		t.Fatalf("expected 123, got %v", val)
	}
}

func TestGetVariantValue_KeyNotFound(t *testing.T) {
	m := map[string]dbus.Variant{}

	_, err := getVariantValue[int](m, "missing")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if err.Error() != "missing not found" {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestGetVariantValue_TypeMismatch(t *testing.T) {
	m := map[string]dbus.Variant{
		"key": dbus.MakeVariant("not-an-int"),
	}

	_, err := getVariantValue[int](m, "key")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

type mockBusObject struct {
	propValue dbus.Variant
	propErr   error
}

func (m *mockBusObject) GetProperty(p string) (dbus.Variant, error) {
	if m.propErr != nil {
		return dbus.Variant{}, m.propErr
	}
	return m.propValue, nil
}

func TestGetPropertyValue_Success(t *testing.T) {
	mock := &mockBusObject{
		propValue: dbus.MakeVariant(true),
	}

	val, err := getPropertyValue[bool](mock, "Some.Prop")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if val != true {
		t.Fatalf("expected true, got %v", val)
	}
}

func TestGetPropertyValue_GetPropertyError(t *testing.T) {
	mock := &mockBusObject{
		propErr: errors.New("dbus failure"),
	}

	_, err := getPropertyValue[bool](mock, "Some.Prop")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if err.Error() != "dbus failure" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetPropertyValue_TypeMismatch(t *testing.T) {
	mock := &mockBusObject{
		propValue: dbus.MakeVariant("wrong-type"),
	}

	_, err := getPropertyValue[int](mock, "Some.Prop")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetSection_Success(t *testing.T) {
	settings := map[string]map[string]dbus.Variant{
		"ipv4": {
			"method": dbus.MakeVariant("auto"),
		},
	}

	sec, err := getSection(settings, "ipv4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := sec["method"]; !ok {
		t.Fatal("expected method key in section")
	}
}

func TestGetSection_NotFound(t *testing.T) {
	settings := map[string]map[string]dbus.Variant{}

	_, err := getSection(settings, "missing")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if err.Error() != "missing section not found" {
		t.Fatalf("unexpected error message: %v", err)
	}
}
