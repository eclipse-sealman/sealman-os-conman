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
package jsonsocket

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"reflect"
	"testing"
)

// BadWriter simulates write errors.
type BadWriter struct {
	FailOnSecondWrite bool
	Writes            int
}

func (b *BadWriter) Write(p []byte) (int, error) {
	b.Writes++
	if !b.FailOnSecondWrite {
		return 0, io.ErrClosedPipe
	}
	if b.Writes == 2 {
		return 0, errors.New("boom on second write")
	}
	return len(p), nil
}

func readResponseFromBuffer(t *testing.T, buf *bytes.Buffer) response {
	t.Helper()

	var length uint32
	if err := binary.Read(buf, binary.BigEndian, &length); err != nil {
		t.Fatalf("failed to read length: %v", err)
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(buf, data); err != nil {
		t.Fatalf("failed to read payload: %v", err)
	}

	var resp response
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	return resp
}

func TestWriteOk_WithBody(t *testing.T) {
	buf := &bytes.Buffer{}

	err := writeOk(buf, map[string]string{"hello": "world"})
	if err != nil {
		t.Fatalf("writeOk failed: %v", err)
	}

	resp := readResponseFromBuffer(t, buf)

	if resp.Status != "OK" {
		t.Fatalf("expected OK status, got %s", resp.Status)
	}

	if resp.Exception != "" {
		t.Fatalf("expected empty exception, got %s", resp.Exception)
	}

	body, ok := resp.Body.(map[string]any)
	if !ok || body["hello"] != "world" {
		t.Fatalf("unexpected body: %+v", resp.Body)
	}
}

func TestWriteOk_NoBody(t *testing.T) {
	buf := &bytes.Buffer{}

	err := writeOk(buf, nil)
	if err != nil {
		t.Fatalf("writeOk failed: %v", err)
	}

	resp := readResponseFromBuffer(t, buf)

	if resp.Status != "OK" {
		t.Fatalf("expected OK status, got %s", resp.Status)
	}

	if resp.Body != nil {
		t.Fatalf("expected nil body, got %+v", resp.Body)
	}
}

func TestWriteFail(t *testing.T) {
	buf := &bytes.Buffer{}

	err := writeFail(buf, errors.New("something went wrong"))
	if err != nil {
		t.Fatalf("writeFail failed: %v", err)
	}

	resp := readResponseFromBuffer(t, buf)

	if resp.Status != "FAIL" {
		t.Fatalf("expected FAIL status, got %s", resp.Status)
	}

	if resp.Exception != "something went wrong" {
		t.Fatalf("unexpected exception: %s", resp.Exception)
	}

	if resp.Body != nil {
		t.Fatalf("expected nil body, got %+v", resp.Body)
	}
}

func TestWriteResponse_JSONMarshalError(t *testing.T) {
	buf := &bytes.Buffer{}

	// functions cannot be marshaled to JSON
	resp := response{
		Status: "OK",
		Body:   func() {},
	}

	err := writeResponse(buf, resp)
	if err == nil {
		t.Fatalf("expected json marshal error")
	}
}

func TestWriteResponse_WriteError(t *testing.T) {
	w := &BadWriter{}

	err := writeOk(w, map[string]string{"k": "v"})
	if err == nil {
		t.Fatalf("expected write error")
	}
}

func writeFrameToBuffer(t *testing.T, payload []byte) *bytes.Buffer {
	t.Helper()

	buf := &bytes.Buffer{}

	length := uint32(len(payload))
	if err := binary.Write(buf, binary.BigEndian, length); err != nil {
		t.Fatalf("failed to write length: %v", err)
	}

	if _, err := buf.Write(payload); err != nil {
		t.Fatalf("failed to write payload: %v", err)
	}

	return buf
}

func TestReadRequest_Valid(t *testing.T) {
	payload := []byte(`{"type":"test"}`)
	buf := writeFrameToBuffer(t, payload)

	req, err := readRequest(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if req.Type != "test" {
		t.Fatalf("expected type test, got %s", req.Type)
	}
}

func TestReadRequest_TooShortLength(t *testing.T) {
	// empty buffer → cannot read 4-byte length
	buf := &bytes.Buffer{}

	_, err := readRequest(buf)
	if !errors.Is(err, ErrRequestTooShort) {
		t.Fatalf("expected ErrRequestTooShort, got %v", err)
	}
}

func TestReadRequest_ZeroLength(t *testing.T) {
	buf := &bytes.Buffer{}

	if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
		t.Fatal(err)
	}

	_, err := readRequest(buf)
	if !errors.Is(err, ErrInvalidRequestLength) {
		t.Fatalf("expected ErrInvalidRequestLength, got %v", err)
	}
}

func TestReadRequest_TooLarge(t *testing.T) {
	buf := &bytes.Buffer{}

	if err := binary.Write(buf, binary.BigEndian, uint32(MaxRequestSize+1)); err != nil {
		t.Fatal(err)
	}

	_, err := readRequest(buf)
	if !errors.Is(err, ErrRequestTooLarge) {
		t.Fatalf("expected ErrRequestTooLarge, got %v", err)
	}
}

func TestReadRequest_TruncatedPayload(t *testing.T) {
	buf := &bytes.Buffer{}

	// Declare length 10 but provide only 5 bytes
	if err := binary.Write(buf, binary.BigEndian, uint32(10)); err != nil {
		t.Fatal(err)
	}

	buf.Write([]byte("12345"))

	_, err := readRequest(buf)
	if !errors.Is(err, ErrRequestTooShort) {
		t.Fatalf("expected ErrRequestTooShort, got %v", err)
	}
}

func TestReadRequest_InvalidJSON(t *testing.T) {
	payload := []byte(`{invalid-json}`)
	buf := writeFrameToBuffer(t, payload)

	_, err := readRequest(buf)
	if err == nil {
		t.Fatalf("expected JSON error")
	}
}

func TestReadRequest_MissingType(t *testing.T) {
	payload := []byte(`{"foo":"bar"}`)
	buf := writeFrameToBuffer(t, payload)

	_, err := readRequest(buf)
	if !errors.Is(err, ErrMissingType) {
		t.Fatalf("expected ErrMissingType, got %v", err)
	}
}

func resetHandlers() {
	handlers = make(map[string]reflect.Value)
}
func TestHandle_Valid(t *testing.T) {
	resetHandlers()

	// No argument, no return
	Handle("noarg", func() {})
	if _, ok := handlers["noarg"]; !ok {
		t.Fatalf("handler was not registered")
	}

	// With argument and return
	type Req struct{ Name string }
	type Resp struct{ Message string }

	Handle("echo", func(r Req) Resp { return Resp{Message: r.Name} })
	if _, ok := handlers["echo"]; !ok {
		t.Fatalf("handler was not registered")
	}
}

func TestHandle_PanicCases(t *testing.T) {
	resetHandlers()

	tests := []struct {
		name string
		fn   any
	}{
		{"not function", 123},
		{"too many args", func(a, b int) {}},
		{"arg not struct", func(a int) {}},
		{"too many returns", func() (int, int) { return 1, 2 }},
		{"return not struct", func() int { return 1 }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Fatalf("expected panic for %s", tt.name)
				}
			}()
			Handle("bad", tt.fn)
		})
	}
}

// CallRaw sends a raw JSON request payload to the connection and returns the response.
// If the server responds with FAIL, an error is returned.
// The caller is responsible for closing conn.
func CallRaw(conn net.Conn, jsonData []byte) (resp response, err error) {
	// write length prefix
	if err := binary.Write(conn, binary.BigEndian, uint32(len(jsonData))); err != nil {
		return resp, err
	}

	// write payload
	if _, err := conn.Write(jsonData); err != nil {
		return resp, err
	}

	// read response length
	var respLen uint32
	if err := binary.Read(conn, binary.BigEndian, &respLen); err != nil {
		return resp, err
	}
	if respLen == 0 {
		return resp, errors.New("response length is zero")
	}
	if respLen > MaxRequestSize {
		return resp, errors.New("response too large")
	}

	respData := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respData); err != nil {
		return resp, err
	}

	if err := json.Unmarshal(respData, &resp); err != nil {
		return resp, err
	}

	if resp.Status == "FAIL" {
		return resp, errors.New(resp.Exception)
	}
	return resp, nil
}

// Call constructs a normal request with a type string and optional JSON body.
func Call(conn net.Conn, msgType string, body any) (response, error) {
	req := request{Type: msgType}
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return response{}, err
		}
		req.Body = data
	}
	data, err := json.Marshal(req)
	if err != nil {
		return response{}, err
	}
	return CallRaw(conn, data)
}

func TestToError_WithError(t *testing.T) {
	orig := errors.New("original")
	err := toError(orig)

	if err != orig {
		t.Fatalf("expected same error instance")
	}
}

func TestToError_WithString(t *testing.T) {
	err := toError("boom")

	if err.Error() != "boom" {
		t.Fatalf("unexpected error message: %s", err.Error())
	}
}

func TestToError_WithOtherType(t *testing.T) {
	err := toError(123)

	if err.Error() != "panic: 123" {
		t.Fatalf("unexpected error message: %s", err.Error())
	}
}

func TestListenAndServe_EndToEndExtended(t *testing.T) {
	resetHandlers()

	type Req struct{ Name string }
	type Resp struct{ Message string }

	// Normal handler
	Handle("greet", func(r Req) Resp {
		return Resp{Message: "hello " + r.Name}
	})

	// Panic handler
	Handle("panic", func() Resp {
		panic("something went wrong")
	})

	// Start TCP listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- ListenAndServe(ln) }()

	// 1. Normal request
	conn1, _ := net.Dial("tcp", ln.Addr().String())
	resp1, err := Call(conn1, "greet", Req{Name: "Alice"})
	conn1.Close()
	if err != nil {
		t.Fatalf("Call failed: %v", err)
	}
	body1 := resp1.Body.(map[string]any)
	if body1["Message"] != "hello Alice" {
		t.Fatalf("unexpected response body: %+v", body1)
	}

	// 2. Panic handler
	conn2, _ := net.Dial("tcp", ln.Addr().String())
	resp2, err := Call(conn2, "panic", nil)
	conn2.Close()
	if err == nil || resp2.Status != "FAIL" || resp2.Exception != "something went wrong" {
		t.Fatalf("unexpected panic response: %+v", resp2)
	}

	// 3. Unknown request type
	conn3, _ := net.Dial("tcp", ln.Addr().String())
	resp3, err := Call(conn3, "unknown_type", nil)
	conn3.Close()
	if err == nil || resp3.Status != "FAIL" || resp3.Exception == "" {
		t.Fatalf("unexpected unknown type response: %+v", resp3)
	}

	// 4. Missing type
	conn4, _ := net.Dial("tcp", ln.Addr().String())
	rawMissingType := []byte(`{"body":{"Name":"Bob"}}`)
	resp4, err := CallRaw(conn4, rawMissingType)
	conn4.Close()
	if err == nil || resp4.Status != "FAIL" || resp4.Exception != "missing type" {
		t.Fatalf("expected missing type FAIL, got %+v", resp4)
	}

	// 5. Invalid JSON
	conn5, _ := net.Dial("tcp", ln.Addr().String())
	rawInvalidJSON := []byte(`{this is invalid json}`)
	resp5, err := CallRaw(conn5, rawInvalidJSON)
	conn5.Close()
	if err == nil || resp5.Status != "FAIL" {
		t.Fatalf("expected FAIL for invalid JSON, got %+v", resp5)
	}

	// 6. Malformed handler body triggers panic
	conn6, _ := net.Dial("tcp", ln.Addr().String())
	// "body" is invalid JSON for the expected struct
	malformedBody := []byte(`{"type":"greet","body":"this should be an object"}`)
	resp6, err := CallRaw(conn6, malformedBody)
	conn6.Close()
	if err == nil {
		t.Fatalf("expected error due to panic in handler argument unmarshalling, got nil")
	}
	if resp6.Status != "FAIL" {
		t.Fatalf("expected FAIL status for malformed handler body, got %+v", resp6)
	}
	if resp6.Exception == "" {
		t.Fatalf("expected exception message for panic during unmarshalling")
	}

	ln.Close()
	<-done
}

type badListener struct{}

func (b *badListener) Accept() (net.Conn, error) { return nil, errors.New("accept failed") }
func (b *badListener) Close() error              { return nil }
func (b *badListener) Addr() net.Addr            { return &net.TCPAddr{} }

func TestListenAndServe_AcceptError(t *testing.T) {
	ln := &badListener{}

	err := ListenAndServe(ln)
	if err == nil {
		t.Fatalf("expected ListenAndServe to return error on accept, got nil")
	}
	if err.Error() != "accept failed" {
		t.Fatalf("unexpected error message: %v", err)
	}
}
