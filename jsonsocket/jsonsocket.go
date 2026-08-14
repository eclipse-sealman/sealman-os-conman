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
//
// Package jsonsocket provides a simple, synchronous JSON-over-TCP
// request/response framework.
//
// # Design
//
// This package is intentionally minimal and synchronous by design.
// Each connection:
//
//  1. Sends exactly one request.
//  2. Receives exactly one response.
//  3. The connection is then closed.
//
// Requests are processed sequentially. There is no internal concurrency.
// The package is NOT thread-safe:
//
//   - Handle must not be called concurrently.
//   - ListenAndServe must not be called concurrently.
//   - Handlers are stored in a global map without synchronization.
//
// This package is intended as a lightweight internal RPC-style mechanism
// for creation of simple daemons running running as a root user.
//
// # Encoding
//
// All messages are JSON encoded using UTF-8, as required by the Go
// encoding/json package and the JSON specification.
//
// # Framing
//
// Messages are framed as:
//
//   - 4-byte big-endian uint32 length prefix
//   - <length> bytes of UTF-8 JSON payload
//
// # Request Format
//
// A request must contain at least:
//
//	{ "type": "handler-name" }
//
// The "type" field is REQUIRED and selects the registered handler.
// The optional "body" field contains JSON-encoded data passed to the handler.
//
// # Maximum Request Size
//
// The maximum allowed request payload size is 1MB (1024 * 1024 bytes).
// Requests exceeding this size result in ErrRequestTooLarge and a FAIL response.
//
// # Error Conditions
//
// The following request-level errors result in a FAIL response:
//
//   - Too short request (invalid or truncated length prefix)
//   - Invalid request length (zero or malformed)
//   - Request size exceeds 1MB (ErrRequestTooLarge)
//   - Invalid JSON
//   - Missing "type" field
//   - Unknown message type
//   - JSON unmarshal error for handler argument
//   - Panic inside handler
//
// # Response Format
//
// The server always responds with exactly one JSON object:
//
//	{ "status": "OK", "body": ... }
//
// or
//
//	{ "status": "FAIL", "exception": "error message" }
//
// The "status" field is always present and is either "OK" or "FAIL".
//
// # Handler Signatures
//
// Supported handler forms:
//
//	func()
//	func() R
//	func(T)
//	func(T) R
//
// T and R must be structs.
//
// # Example Usage
//
//	type GreetRequest struct {
//	    Name string
//	}
//
//	type GreetResponse struct {
//	    Message string
//	}
//
//	type SumRequest struct {
//	    A, B int
//	}
//
//	type SumResponse struct {
//	    Result int
//	}
//
// // Handler with argument and return value
//
//	jsonsocket.Handle("greet", func(req GreetRequest) GreetResponse {
//	    return GreetResponse{Message: "Hello, " + req.Name}
//	})
//
// // Handler with argument and return value
//
//	jsonsocket.Handle("sum", func(req SumRequest) SumResponse {
//	    return SumResponse{Result: req.A + req.B}
//	})
//
// // Handler without arguments and without return value
//
//	jsonsocket.Handle("ping", func() {
//	    fmt.Println("Received ping")
//	})
//
//	ln, err := net.Listen("unix", "/tmp/foo.sock")
//
//	if err != nil {
//	    panic(err)
//	}
//
//	if err := jsonsocket.ListenAndServe(ln); err != nil {
//	    panic(err)
//	}
package jsonsocket

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os/signal"
	"reflect"
	"syscall"
)

const (
	// MaxRequestSize defines the maximum allowed size in bytes
	// of an incoming request payload (JSON body).
	MaxRequestSize = 1024 * 1024 // 1MB
)

var (
	// ErrRequestTooShort indicates that the request frame
	// could not be fully read (truncated or incomplete).
	ErrRequestTooShort = errors.New("request too short")

	// ErrInvalidRequestLength indicates that the request length
	// prefix is zero or otherwise invalid.
	ErrInvalidRequestLength = errors.New("invalid request length")

	// ErrRequestTooLarge is returned when the incoming request
	// exceeds MaxRequestSize.
	ErrRequestTooLarge = errors.New("request too large")

	// ErrMissingType indicates that the JSON request does not
	// contain the required "type" field.
	ErrMissingType = errors.New("missing type")

	// ErrUnknownType indicates that no handler is registered
	// for the requested message type.
	ErrUnknownType = errors.New("unknown message type")
)

// request represents a client request.
// "Type" identifies the handler to call.
// "Body" contains optional JSON-encoded data.
type request struct {
	Type string          `json:"type"`
	Body json.RawMessage `json:"body,omitempty"`
}

// response represents a server response.
// Status is either "OK" or "FAIL".
// Body contains optional JSON data if Status is "OK".
// Exception contains the error string if Status is "FAIL".
type response struct {
	Status    string `json:"status"`              // "OK" or "FAIL"
	Body      any    `json:"body,omitempty"`      // optional
	Exception string `json:"exception,omitempty"` // only on FAIL
}

// handlers stores registered message handlers keyed by type.
var handlers = make(map[string]reflect.Value)

// Handle registers a handler function for a given message type.
//
// Allowed handler signatures:
//
//	func()
//	func() R
//	func(T)
//	func(T) R
//
// T and R must be structs. Panics inside the handler are recovered
// and returned as a FAIL response.
func Handle(msgType string, handler any) {
	v := reflect.ValueOf(handler)
	t := v.Type()

	if t.Kind() != reflect.Func {
		panic("handler must be a function")
	}

	if t.NumIn() > 1 {
		panic("handler may have zero or one argument")
	}
	if t.NumIn() == 1 && t.In(0).Kind() != reflect.Struct {
		panic("handler argument must be struct")
	}

	if t.NumOut() > 1 {
		panic("handler may have zero or one return value")
	}
	if t.NumOut() == 1 && t.Out(0).Kind() != reflect.Struct {
		panic("return value must be struct")
	}

	handlers[msgType] = v
}

// ListenAndServe accepts connections from the provided net.Listener
// and handles requests synchronously. Each connection expects a single
// request. Returns an error if accepting connections fails.
func ListenAndServe(l net.Listener) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		if l != nil {
			l.Close()
		}
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		handleConn(conn)
	}
}

// handleConn reads a single request, safely calls the handler,
// and writes a single response. Any panic during handling is
// recovered and sent as a FAIL response.
func handleConn(conn net.Conn) {
	defer conn.Close()

	defer func() {
		if r := recover(); r != nil {
			writeFail(conn, toError(r))
		}
	}()

	req, err := readRequest(conn)
	if err != nil {
		writeFail(conn, err)
		return
	}

	handler, ok := handlers[req.Type]
	if !ok {
		writeFail(conn, fmt.Errorf("%w: %s", ErrUnknownType, req.Type))
		return
	}

	handlerType := handler.Type()
	var args []reflect.Value

	if handlerType.NumIn() == 1 {
		argPtr := reflect.New(handlerType.In(0))
		if len(req.Body) > 0 {
			if err := json.Unmarshal(req.Body, argPtr.Interface()); err != nil {
				panic(err)
			}
		}
		args = []reflect.Value{argPtr.Elem()}
	}

	returnValues := handler.Call(args)

	var resp any
	if handlerType.NumOut() == 1 {
		resp = returnValues[0].Interface()
	}

	writeOk(conn, resp)
}

// readRequest reads a request from the connection.
//
// The request must begin with a 4-byte big-endian uint32 length
// followed by a JSON payload. If the declared length exceeds
// MaxRequestSize, ErrRequestTooLarge is returned.
func readRequest(r io.Reader) (*request, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, ErrRequestTooShort
	}

	if length == 0 {
		return nil, ErrInvalidRequestLength
	}

	if length > MaxRequestSize {
		return nil, ErrRequestTooLarge
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, ErrRequestTooShort
	}

	var req request
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, err
	}

	if req.Type == "" {
		return nil, ErrMissingType
	}

	return &req, nil
}

// writeOk writes a response with Status "OK" and optional body.
func writeOk(w io.Writer, body any) error {
	resp := response{Status: "OK"}
	if body != nil {
		resp.Body = body
	}
	return writeResponse(w, resp)
}

// writeFail writes a response with Status "FAIL" and exception string.
func writeFail(w io.Writer, err error) error {
	return writeResponse(w, response{
		Status:    "FAIL",
		Exception: err.Error(),
	})
}

// writeResponse encodes and sends a response with 4-byte length prefix.
func writeResponse(w io.Writer, resp response) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	length := uint32(len(data))
	if err := binary.Write(w, binary.BigEndian, length); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// toError converts recovered panic values to an error.
func toError(v any) error {
	switch e := v.(type) {
	case error:
		return e
	case string:
		return errors.New(e)
	default:
		return fmt.Errorf("panic: %v", e)
	}
}
