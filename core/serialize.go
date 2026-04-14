// Copyright (C) 2024 The OpenTimestamps developers
//
// Go rewrite of python-opentimestamps.
// SPDX-License-Identifier: LGPL-3.0-or-later

// Package core implements the consensus-critical serialization, operations,
// attestations, and timestamp tree for the OpenTimestamps protocol.
package core

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
)

// --- Error types ---

// DeserializationError is the base type for errors encountered during deserialization.
type DeserializationError struct{ msg string }

func (e *DeserializationError) Error() string { return e.msg }

func newDeserializationError(format string, args ...any) error {
	return &DeserializationError{msg: fmt.Sprintf(format, args...)}
}

// BadMagicError is returned when magic bytes do not match.
type BadMagicError struct {
	Expected []byte
	Actual   []byte
}

func (e *BadMagicError) Error() string {
	return fmt.Sprintf("expected magic bytes 0x%s, but got 0x%s instead",
		hex.EncodeToString(e.Expected), hex.EncodeToString(e.Actual))
}

// UnsupportedMajorVersion is returned when the file's major version is not supported.
type UnsupportedMajorVersion struct{ Version int }

func (e *UnsupportedMajorVersion) Error() string {
	return fmt.Sprintf("version %d detached timestamp files are not supported", e.Version)
}

// TruncationError is returned when the data ends prematurely.
type TruncationError struct{ msg string }

func (e *TruncationError) Error() string { return e.msg }

// TrailingGarbageError is returned when unexpected bytes follow the serialized data.
type TrailingGarbageError struct{ msg string }

func (e *TrailingGarbageError) Error() string { return e.msg }

// RecursionLimitError is returned when the recursion depth limit is exceeded.
type RecursionLimitError struct{ msg string }

func (e *RecursionLimitError) Error() string { return e.msg }

// --- Serialization context ---

// SerializationContext is the interface for writing serialized data.
type SerializationContext interface {
	WriteBytes(b []byte) error
	WriteUint8(v uint8) error
	WriteVarUint(v uint64) error
	WriteVarBytes(b []byte) error
}

// DeserializationContext is the interface for reading serialized data.
type DeserializationContext interface {
	ReadBytes(n int) ([]byte, error)
	ReadUint8() (uint8, error)
	ReadVarUint() (uint64, error)
	ReadVarBytes(maxLen int) ([]byte, error)
	ReadVarBytesMinMax(minLen, maxLen int) ([]byte, error)
	AssertMagic(magic []byte) error
	AssertEOF() error
}

// --- Stream implementations ---

// StreamSerializationContext writes to an io.Writer.
type StreamSerializationContext struct{ w io.Writer }

// NewStreamSerializationContext creates a StreamSerializationContext writing to w.
func NewStreamSerializationContext(w io.Writer) *StreamSerializationContext {
	return &StreamSerializationContext{w: w}
}

func (c *StreamSerializationContext) WriteBytes(b []byte) error {
	_, err := c.w.Write(b)
	return err
}

func (c *StreamSerializationContext) WriteUint8(v uint8) error {
	_, err := c.w.Write([]byte{v})
	return err
}

// WriteVarUint writes an unsigned LEB128 varint.
func (c *StreamSerializationContext) WriteVarUint(v uint64) error {
	if v == 0 {
		_, err := c.w.Write([]byte{0x00})
		return err
	}
	for v != 0 {
		b := byte(v & 0x7f)
		if v > 0x7f {
			b |= 0x80
		}
		if _, err := c.w.Write([]byte{b}); err != nil {
			return err
		}
		if v <= 0x7f {
			break
		}
		v >>= 7
	}
	return nil
}

func (c *StreamSerializationContext) WriteVarBytes(b []byte) error {
	if err := c.WriteVarUint(uint64(len(b))); err != nil {
		return err
	}
	return c.WriteBytes(b)
}

// StreamDeserializationContext reads from an io.Reader.
type StreamDeserializationContext struct{ r io.Reader }

// NewStreamDeserializationContext creates a StreamDeserializationContext reading from r.
func NewStreamDeserializationContext(r io.Reader) *StreamDeserializationContext {
	return &StreamDeserializationContext{r: r}
}

func (c *StreamDeserializationContext) ReadBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(c.r, buf)
	if err != nil {
		return nil, &TruncationError{msg: fmt.Sprintf("tried to read %d bytes: %s", n, err)}
	}
	return buf, nil
}

func (c *StreamDeserializationContext) ReadUint8() (uint8, error) {
	b, err := c.ReadBytes(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

// ReadVarUint reads an unsigned LEB128 varint.
func (c *StreamDeserializationContext) ReadVarUint() (uint64, error) {
	var value uint64
	var shift uint
	for {
		b, err := c.ReadUint8()
		if err != nil {
			return 0, err
		}
		value |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
	}
	return value, nil
}

func (c *StreamDeserializationContext) ReadVarBytes(maxLen int) ([]byte, error) {
	return c.ReadVarBytesMinMax(0, maxLen)
}

func (c *StreamDeserializationContext) ReadVarBytesMinMax(minLen, maxLen int) ([]byte, error) {
	l, err := c.ReadVarUint()
	if err != nil {
		return nil, err
	}
	if int(l) > maxLen {
		return nil, newDeserializationError("varbytes max length exceeded; %d > %d", l, maxLen)
	}
	if int(l) < minLen {
		return nil, newDeserializationError("varbytes min length not met; %d < %d", l, minLen)
	}
	return c.ReadBytes(int(l))
}

func (c *StreamDeserializationContext) AssertMagic(magic []byte) error {
	actual, err := c.ReadBytes(len(magic))
	if err != nil {
		return &BadMagicError{Expected: magic, Actual: actual}
	}
	if !bytes.Equal(magic, actual) {
		return &BadMagicError{Expected: magic, Actual: actual}
	}
	return nil
}

func (c *StreamDeserializationContext) AssertEOF() error {
	buf := make([]byte, 1)
	n, _ := c.r.Read(buf)
	if n > 0 {
		return &TrailingGarbageError{msg: "trailing garbage found after end of deserialized data"}
	}
	return nil
}

// --- Bytes implementations ---

// BytesSerializationContext serializes to a byte buffer.
type BytesSerializationContext struct{ StreamSerializationContext; buf bytes.Buffer }

// NewBytesSerializationContext creates a BytesSerializationContext.
func NewBytesSerializationContext() *BytesSerializationContext {
	c := &BytesSerializationContext{}
	c.w = &c.buf
	return c
}

// GetBytes returns the bytes written so far.
func (c *BytesSerializationContext) GetBytes() []byte { return c.buf.Bytes() }

// BytesDeserializationContext deserializes from a byte slice.
type BytesDeserializationContext struct{ StreamDeserializationContext }

// NewBytesDeserializationContext creates a BytesDeserializationContext reading from buf.
func NewBytesDeserializationContext(buf []byte) *BytesDeserializationContext {
	return &BytesDeserializationContext{StreamDeserializationContext{r: bytes.NewReader(buf)}}
}
