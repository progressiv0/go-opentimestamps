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

	"github.com/progressiv0/go-opentimestamps/core"
)

func TestAddOp(t *testing.T) {
	ts := core.MustNewTimestamp([]byte("abcd"))
	appendOp, _ := core.NewOpAppend([]byte("efgh"))
	child := ts.Ops.Add(appendOp)
	if !bytes.Equal(child.Msg, []byte("abcdefgh")) {
		t.Errorf("child.Msg: got %q, want %q", child.Msg, "abcdefgh")
	}
	// Second add should return the same timestamp
	child2 := ts.Ops.Add(appendOp)
	if child != child2 {
		t.Error("second Add should return the same Timestamp pointer")
	}
}

func TestMerge(t *testing.T) {
	t1 := core.MustNewTimestamp([]byte("a"))
	t2 := core.MustNewTimestamp([]byte("b"))
	if err := t1.Merge(t2); err == nil {
		t.Error("merging timestamps for different messages should fail")
	}

	t3 := core.MustNewTimestamp([]byte("a"))
	t4 := core.MustNewTimestamp([]byte("a"))
	t4.AddAttestation(&core.PendingAttestation{URI: "foobar"})
	if err := t3.Merge(t4); err != nil {
		t.Fatal(err)
	}
	if !t3.Equal(t4) {
		t.Error("after merge, t3 should equal t4")
	}
}

func TestTimestampSerialization(t *testing.T) {
	pendingTag, _ := hex.DecodeString("83dfe30d2ef90c8e")

	// Single pending attestation
	stamp := core.MustNewTimestamp([]byte("foo"))
	stamp.AddAttestation(&core.PendingAttestation{URI: "foobar"})

	// Expected: 0x00 + pendingTag + 07 + 06 + foobar
	expected := append([]byte{0x00}, pendingTag...)
	expected = append(expected, 0x07, 0x06)
	expected = append(expected, []byte("foobar")...)

	ctx := core.NewBytesSerializationContext()
	if err := stamp.Serialize(ctx); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ctx.GetBytes(), expected) {
		t.Errorf("single attestation: got %x, want %x", ctx.GetBytes(), expected)
	}

	// Round trip
	dctx := core.NewBytesDeserializationContext(expected)
	got, err := core.DeserializeTimestamp(dctx, []byte("foo"), 256)
	if err != nil {
		t.Fatal(err)
	}
	if !stamp.Equal(got) {
		t.Error("round-trip failed")
	}
}

func TestTimestampSerializationTwoAttestations(t *testing.T) {
	pendingTag, _ := hex.DecodeString("83dfe30d2ef90c8e")
	stamp := core.MustNewTimestamp([]byte("foo"))
	stamp.AddAttestation(&core.PendingAttestation{URI: "foobar"})
	stamp.AddAttestation(&core.PendingAttestation{URI: "barfoo"})

	// barfoo < foobar lexicographically, so barfoo comes first
	var expected []byte
	expected = append(expected, 0xff)
	expected = append(expected, 0x00)
	expected = append(expected, pendingTag...)
	expected = append(expected, 0x07, 0x06)
	expected = append(expected, []byte("barfoo")...)
	expected = append(expected, 0x00)
	expected = append(expected, pendingTag...)
	expected = append(expected, 0x07, 0x06)
	expected = append(expected, []byte("foobar")...)

	ctx := core.NewBytesSerializationContext()
	if err := stamp.Serialize(ctx); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ctx.GetBytes(), expected) {
		t.Errorf("two attestations: got %x, want %x", ctx.GetBytes(), expected)
	}
}

func TestTimestampEmptySerializationFails(t *testing.T) {
	stamp := core.MustNewTimestamp([]byte("foo"))
	stamp.AddAttestation(&core.PendingAttestation{URI: "foobaz"})
	stamp.AddAttestation(&core.PendingAttestation{URI: "foobar"})
	stamp.AddAttestation(&core.PendingAttestation{URI: "barfoo"})
	// Add sha256 op but do not add attestation to it
	_ = stamp.Ops.Add(core.OpSHA256{})

	ctx := core.NewBytesSerializationContext()
	if err := stamp.Serialize(ctx); err == nil {
		t.Error("expected error serializing timestamp with empty branch")
	}
}

func TestTimestampRecursionLimit(t *testing.T) {
	// 256 nested OpSHA256s then a pending attestation
	pendingTag, _ := hex.DecodeString("83dfe30d2ef90c8e")
	var serialized []byte
	for i := 0; i < 256; i++ {
		serialized = append(serialized, 0x08) // OpSHA256 tag
	}
	serialized = append(serialized, 0x00)
	serialized = append(serialized, pendingTag...)
	serialized = append(serialized, 0x07, 0x06)
	serialized = append(serialized, []byte("barfoo")...)

	dctx := core.NewBytesDeserializationContext(serialized)
	_, err := core.DeserializeTimestamp(dctx, []byte{}, 256)
	if err == nil {
		t.Error("expected RecursionLimitError")
	}
	if _, ok := err.(*core.RecursionLimitError); !ok {
		t.Errorf("expected *RecursionLimitError, got %T: %v", err, err)
	}
}

func TestStrTree(t *testing.T) {
	ts := core.MustNewTimestamp([]byte{})
	appendOp, _ := core.NewOpAppend([]byte{0x01})
	ts.Ops.Add(appendOp)
	ts.Ops.Add(core.OpSHA256{})

	tree := ts.StrTree(0, 0)
	if !strings.Contains(tree, "sha256") {
		t.Errorf("StrTree should contain 'sha256', got: %q", tree)
	}
	if !strings.Contains(tree, "append") {
		t.Errorf("StrTree should contain 'append', got: %q", tree)
	}
}

func TestTimestampEquality(t *testing.T) {
	t1 := core.MustNewTimestamp([]byte{})
	t1.AddAttestation(&core.BitcoinBlockHeaderAttestation{Height: 1})
	t1.AddAttestation(&core.PendingAttestation{URI: ""})

	t2 := core.MustNewTimestamp([]byte{})
	if t1.Equal(t2) {
		t.Error("timestamps with different attestations should not be equal")
	}

	t2.AddAttestation(&core.PendingAttestation{URI: ""})
	t2.AddAttestation(&core.BitcoinBlockHeaderAttestation{Height: 1})
	if !t1.Equal(t2) {
		t.Error("timestamps with same attestations should be equal regardless of order")
	}
}

func TestDetachedTimestampFileFromReader(t *testing.T) {
	dt, err := core.DetachedTimestampFileFromReader(core.OpSHA256{}, bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	if !bytes.Equal(dt.FileDigest(), want) {
		t.Errorf("file digest: got %x, want %x", dt.FileDigest(), want)
	}
}

func TestDetachedTimestampFileSerialization(t *testing.T) {
	dt, _ := core.DetachedTimestampFileFromReader(core.OpSHA256{}, bytes.NewReader(nil))
	dt.Timestamp.AddAttestation(&core.PendingAttestation{URI: "foobar"})

	pendingTag, _ := hex.DecodeString("83dfe30d2ef90c8e")
	sha256Hash, _ := hex.DecodeString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

	var expected []byte
	expected = append(expected, core.HEADER_MAGIC...)
	expected = append(expected, 0x01) // major version
	expected = append(expected, 0x08) // SHA256 tag
	expected = append(expected, sha256Hash...)
	expected = append(expected, 0x00)
	expected = append(expected, pendingTag...)
	expected = append(expected, 0x07, 0x06)
	expected = append(expected, []byte("foobar")...)

	ctx := core.NewBytesSerializationContext()
	if err := dt.Serialize(ctx); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ctx.GetBytes(), expected) {
		t.Errorf("serialize: got %x, want %x", ctx.GetBytes(), expected)
	}

	// Round trip
	dctx := core.NewBytesDeserializationContext(expected)
	got, err := core.DeserializeDetachedTimestampFile(dctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.FileDigest(), dt.FileDigest()) {
		t.Errorf("round-trip file digest mismatch")
	}
}

func TestDetachedTimestampFileDeserializationFailures(t *testing.T) {
	pendingTag, _ := hex.DecodeString("83dfe30d2ef90c8e")
	sha256Hash, _ := hex.DecodeString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

	validBase := func() []byte {
		var b []byte
		b = append(b, core.HEADER_MAGIC...)
		b = append(b, 0x01, 0x08)
		b = append(b, sha256Hash...)
		b = append(b, 0x00)
		b = append(b, pendingTag...)
		b = append(b, 0x07, 0x06)
		b = append(b, []byte("foobar")...)
		return b
	}

	// Empty data → BadMagicError
	dctx := core.NewBytesDeserializationContext(nil)
	if _, err := core.DeserializeDetachedTimestampFile(dctx); err == nil {
		t.Error("expected error for empty data")
	}

	// Wrong magic
	wrong := append([]byte("\x00Not a OpenTimestamps Proof \x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94\x01"), 0x00)
	dctx = core.NewBytesDeserializationContext(wrong)
	if _, err := core.DeserializeDetachedTimestampFile(dctx); err == nil {
		t.Error("expected error for wrong magic")
	}

	// Version 0 (unsupported)
	v0 := append(core.HEADER_MAGIC, 0x00)
	dctx = core.NewBytesDeserializationContext(v0)
	if _, err := core.DeserializeDetachedTimestampFile(dctx); err == nil {
		t.Error("expected error for version 0")
	}

	// Trailing garbage
	trailing := append(validBase(), []byte("trailing garbage")...)
	dctx = core.NewBytesDeserializationContext(trailing)
	if _, err := core.DeserializeDetachedTimestampFile(dctx); err == nil {
		t.Error("expected error for trailing garbage")
	}
}

func TestCatSHA256(t *testing.T) {
	left := core.MustNewTimestamp([]byte("foo"))
	right := core.MustNewTimestamp([]byte("bar"))
	stamp := core.CatSHA256(left, right)

	want, _ := hex.DecodeString("c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2")
	if !bytes.Equal(stamp.Msg, want) {
		t.Errorf("CatSHA256(foo, bar): got %x, want %x", stamp.Msg, want)
	}

	righter := core.MustNewTimestamp([]byte("baz"))
	stamp2 := core.CatSHA256(stamp, righter)
	want2, _ := hex.DecodeString("23388b16c66f1fa37ef14af8eb081712d570813e2afb8c8ae86efa726f3b7276")
	if !bytes.Equal(stamp2.Msg, want2) {
		t.Errorf("CatSHA256(cat(foo,bar), baz): got %x, want %x", stamp2.Msg, want2)
	}
}

func TestMakeMerkleTree(t *testing.T) {
	cases := []struct {
		n    int
		want string
	}{
		{1, "00"},
		{2, "b413f47d13ee2fe6c845b2ee141af81de858df4ec549a58b7970bb96645bc8d2"},
		{3, "e6aa639123d8aac95d13d365ec3779dade4b49c083a8fed97d7bfc0d89bb6a5e"},
		{4, "7699a4fdd6b8b6908a344f73b8f05c8e1400f7253f544602c442ff5c65504b24"},
		{5, "aaa9609d0c949fee22c1c941a4432f32dc1c2de939e4af25207f0dc62df0dbd8"},
		{6, "ebdb4245f648b7e77b60f4f8a99a6d0529d1d372f98f35478b3284f16da93c06"},
		{7, "ba4603a311279dea32e8958bfb660c86237157bf79e6bfee857803e811d91b8f"},
	}

	for _, tc := range cases {
		stamps := make([]*core.Timestamp, tc.n)
		for i := range stamps {
			stamps[i] = core.MustNewTimestamp([]byte{byte(i)})
		}
		tip := core.MakeMerkleTree(stamps)

		want, _ := hex.DecodeString(tc.want)
		if !bytes.Equal(tip.Msg, want) {
			t.Errorf("MakeMerkleTree(%d): got %x, want %x", tc.n, tip.Msg, want)
		}
	}
}
