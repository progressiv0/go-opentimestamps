// Copyright (C) 2024 The OpenTimestamps developers
//
// Go rewrite of python-opentimestamps.
// SPDX-License-Identifier: LGPL-3.0-or-later

package core_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/opentimestamps/go-opentimestamps/core"
)

func TestOpAppend(t *testing.T) {
	op, err := core.NewOpAppend([]byte("suffix"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := op.Apply([]byte("msg"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("msgsuffix")) {
		t.Errorf("got %q, want %q", got, "msgsuffix")
	}
}

func TestOpAppendInvalidArg(t *testing.T) {
	_, err := core.NewOpAppend(nil)
	if err == nil {
		t.Error("expected error for nil arg")
	}
	_, err = core.NewOpAppend([]byte{})
	if err == nil {
		t.Error("expected error for empty arg")
	}
	_, err = core.NewOpAppend(bytes.Repeat([]byte("."), 4097))
	if err == nil {
		t.Error("expected error for arg > 4096 bytes")
	}
}

func TestOpAppendInvalidMsg(t *testing.T) {
	op, _ := core.NewOpAppend([]byte("."))
	// 4095 bytes should be ok
	if _, err := op.Apply(bytes.Repeat([]byte("."), 4095)); err != nil {
		t.Errorf("unexpected error for 4095-byte msg: %v", err)
	}
	// 4096 bytes should fail
	if _, err := op.Apply(bytes.Repeat([]byte("."), 4096)); err == nil {
		t.Error("expected error for 4096-byte msg")
	}
}

func TestOpPrepend(t *testing.T) {
	op, err := core.NewOpPrepend([]byte("prefix"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := op.Apply([]byte("msg"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("prefixmsg")) {
		t.Errorf("got %q, want %q", got, "prefixmsg")
	}
}

func TestOpHexlify(t *testing.T) {
	cases := []struct {
		input    []byte
		expected []byte
	}{
		{[]byte{0x00}, []byte("00")},
		{[]byte{0xde, 0xad, 0xbe, 0xef}, []byte("deadbeef")},
	}
	op := core.OpHexlify{}
	for _, tc := range cases {
		got, err := op.Apply(tc.input)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, tc.expected) {
			t.Errorf("hexlify(%x): got %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestOpHexlifyLengthLimits(t *testing.T) {
	op := core.OpHexlify{}
	if _, err := op.Apply(bytes.Repeat([]byte("."), 2048)); err != nil {
		t.Errorf("unexpected error for 2048-byte msg: %v", err)
	}
	if _, err := op.Apply(bytes.Repeat([]byte("."), 2049)); err == nil {
		t.Error("expected error for 2049-byte msg")
	}
	if _, err := op.Apply(nil); err == nil {
		t.Error("expected error for empty msg")
	}
}

func TestOpSHA256(t *testing.T) {
	op := core.OpSHA256{}
	got, err := op.Apply([]byte{})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	if !bytes.Equal(got, want) {
		t.Errorf("sha256(''): got %x, want %x", got, want)
	}
}

func TestOpRIPEMD160(t *testing.T) {
	op := core.OpRIPEMD160{}
	got, err := op.Apply([]byte{})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("9c1185a5c5e9fc54612808977ee8f548b2258d31")
	if !bytes.Equal(got, want) {
		t.Errorf("ripemd160(''): got %x, want %x", got, want)
	}
}

func TestOpKECCAK256(t *testing.T) {
	op := core.OpKECCAK256{}

	got, err := op.Apply([]byte{})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
	if !bytes.Equal(got, want) {
		t.Errorf("keccak256(''): got %x, want %x", got, want)
	}

	got2, err := op.Apply([]byte{0x80})
	if err != nil {
		t.Fatal(err)
	}
	want2, _ := hex.DecodeString("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
	if !bytes.Equal(got2, want2) {
		t.Errorf("keccak256('\\x80'): got %x, want %x", got2, want2)
	}
}

func TestOpEquality(t *testing.T) {
	if !(core.OpReverse{}).Equal(core.OpReverse{}) {
		t.Error("OpReverse should equal OpReverse")
	}
	if (core.OpReverse{}).Equal(core.OpSHA1{}) {
		t.Error("OpReverse should not equal OpSHA1")
	}

	a1, _ := core.NewOpAppend([]byte("foo"))
	a2, _ := core.NewOpAppend([]byte("foo"))
	a3, _ := core.NewOpAppend([]byte("bar"))
	p1, _ := core.NewOpPrepend([]byte("foo"))
	if !a1.Equal(a2) {
		t.Error("OpAppend(foo) should equal OpAppend(foo)")
	}
	if a1.Equal(a3) {
		t.Error("OpAppend(foo) should not equal OpAppend(bar)")
	}
	if a1.Equal(p1) {
		t.Error("OpAppend(foo) should not equal OpPrepend(foo)")
	}
}

func TestOpOrdering(t *testing.T) {
	if !(core.OpSHA1{}).Less(core.OpRIPEMD160{}) {
		t.Error("SHA1 (0x02) should be less than RIPEMD160 (0x03)")
	}
}

func TestOpSerialize(t *testing.T) {
	// Test serialize/deserialize round trip for all ops
	ops := []core.Op{
		core.OpSHA1{},
		core.OpRIPEMD160{},
		core.OpSHA256{},
		core.OpKECCAK256{},
		core.OpReverse{},
		core.OpHexlify{},
	}
	appendOp, _ := core.NewOpAppend([]byte("hello"))
	prependOp, _ := core.NewOpPrepend([]byte("world"))
	ops = append(ops, appendOp, prependOp)

	for _, op := range ops {
		ctx := core.NewBytesSerializationContext()
		if err := op.Serialize(ctx); err != nil {
			t.Fatalf("Serialize(%T): %v", op, err)
		}
		data := ctx.GetBytes()

		dctx := core.NewBytesDeserializationContext(data)
		tag, err := dctx.ReadUint8()
		if err != nil {
			t.Fatalf("ReadUint8 for %T: %v", op, err)
		}
		got, err := core.DeserializeOpFromTag(dctx, tag)
		if err != nil {
			t.Fatalf("DeserializeOpFromTag for %T: %v", op, err)
		}
		if !op.Equal(got) {
			t.Errorf("round trip failed for %T: got %T", op, got)
		}
	}
}

func TestOpStrings(t *testing.T) {
	cases := []struct {
		op   core.Op
		want string
	}{
		{core.OpSHA1{}, "sha1"},
		{core.OpRIPEMD160{}, "ripemd160"},
		{core.OpSHA256{}, "sha256"},
		{core.OpKECCAK256{}, "keccak256"},
		{core.OpReverse{}, "reverse"},
		{core.OpHexlify{}, "hexlify"},
	}
	for _, tc := range cases {
		if got := tc.op.String(); !strings.EqualFold(got, tc.want) {
			t.Errorf("%T.String(): got %q, want %q", tc.op, got, tc.want)
		}
	}
}
