// Copyright (C) 2024 The OpenTimestamps developers
//
// Go rewrite of python-opentimestamps.
// SPDX-License-Identifier: LGPL-3.0-or-later

package core_test

import (
	"testing"

	"github.com/progressiv0/go-opentimestamps/core"
)

func TestAssertEOF(t *testing.T) {
	ctx := core.NewBytesDeserializationContext(nil)
	if err := ctx.AssertEOF(); err != nil {
		t.Fatalf("expected no error on empty buffer, got: %v", err)
	}

	ctx2 := core.NewBytesDeserializationContext([]byte("b"))
	if err := ctx2.AssertEOF(); err == nil {
		t.Fatal("expected TrailingGarbageError, got nil")
	}
}

func TestVarUint(t *testing.T) {
	cases := []struct {
		value    uint64
		expected []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{127, []byte{0x7f}},
		{128, []byte{0x80, 0x01}},
		{255, []byte{0xff, 0x01}},
		{300, []byte{0xac, 0x02}},
	}

	for _, tc := range cases {
		ctx := core.NewBytesSerializationContext()
		if err := ctx.WriteVarUint(tc.value); err != nil {
			t.Fatalf("WriteVarUint(%d): %v", tc.value, err)
		}
		if got := ctx.GetBytes(); string(got) != string(tc.expected) {
			t.Errorf("WriteVarUint(%d): got %x, want %x", tc.value, got, tc.expected)
		}

		dctx := core.NewBytesDeserializationContext(tc.expected)
		v, err := dctx.ReadVarUint()
		if err != nil {
			t.Fatalf("ReadVarUint(%x): %v", tc.expected, err)
		}
		if v != tc.value {
			t.Errorf("ReadVarUint(%x): got %d, want %d", tc.expected, v, tc.value)
		}
	}
}
