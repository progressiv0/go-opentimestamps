// Copyright (C) 2024 The OpenTimestamps developers
//
// Go rewrite of python-opentimestamps.
// SPDX-License-Identifier: LGPL-3.0-or-later

package core_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/progressiv0/go-opentimestamps/core"
)

func TestPendingAttestationSerialize(t *testing.T) {
	att := &core.PendingAttestation{URI: "foobar"}
	expected, _ := hex.DecodeString("83dfe30d2ef90c8e" + "07" + "06")
	expected = append(expected, []byte("foobar")...)

	ctx := core.NewBytesSerializationContext()
	if err := att.Serialize(ctx); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ctx.GetBytes(), expected) {
		t.Errorf("serialize: got %x, want %x", ctx.GetBytes(), expected)
	}

	dctx := core.NewBytesDeserializationContext(expected)
	att2, err := core.DeserializeAttestation(dctx)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := att2.(*core.PendingAttestation)
	if !ok {
		t.Fatalf("expected *PendingAttestation, got %T", att2)
	}
	if p.URI != "foobar" {
		t.Errorf("URI: got %q, want %q", p.URI, "foobar")
	}
}

func TestPendingAttestationInvalidURI(t *testing.T) {
	// illegal character %
	badData, _ := hex.DecodeString("83dfe30d2ef90c8e" + "07" + "06")
	badData = append(badData, []byte("fo%bar")...)
	dctx := core.NewBytesDeserializationContext(badData)
	if _, err := core.DeserializeAttestation(dctx); err == nil {
		t.Error("expected error for invalid URI character")
	}

	// Exactly 1000-byte URI is ok
	var lenBuf bytes.Buffer
	lenCtx := core.NewStreamSerializationContext(&lenBuf)
	_ = lenCtx.WriteVarUint(1000)
	var innerLenBuf bytes.Buffer
	innerCtx := core.NewStreamSerializationContext(&innerLenBuf)
	_ = innerCtx.WriteVarUint(1000)
	tag, _ := hex.DecodeString("83dfe30d2ef90c8e")
	good := append(tag, prependVarBytes(t, append(innerLenBuf.Bytes(), bytes.Repeat([]byte("x"), 1000)...))...)
	dctx2 := core.NewBytesDeserializationContext(good)
	if _, err := core.DeserializeAttestation(dctx2); err != nil {
		t.Errorf("1000-byte URI should be valid: %v", err)
	}
}

func prependVarBytes(t *testing.T, data []byte) []byte {
	ctx := core.NewBytesSerializationContext()
	if err := ctx.WriteVarUint(uint64(len(data))); err != nil {
		t.Fatal(err)
	}
	return append(ctx.GetBytes(), data...)
}

func TestUnknownAttestationSerialize(t *testing.T) {
	tag, _ := hex.DecodeString("0102030405060708")
	expected := append(tag, byte(12))
	expected = append(expected, []byte("Hello World!")...)

	dctx := core.NewBytesDeserializationContext(expected)
	att, err := core.DeserializeAttestation(dctx)
	if err != nil {
		t.Fatal(err)
	}
	u, ok := att.(*core.UnknownAttestation)
	if !ok {
		t.Fatalf("expected *UnknownAttestation, got %T", att)
	}
	if !bytes.Equal(u.TagBytes(), tag) {
		t.Errorf("tag: got %x, want %x", u.TagBytes(), tag)
	}
	if !bytes.Equal(u.Payload, []byte("Hello World!")) {
		t.Errorf("payload: got %q, want %q", u.Payload, "Hello World!")
	}

	// Round trip
	ctx := core.NewBytesSerializationContext()
	if err := att.Serialize(ctx); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ctx.GetBytes(), expected) {
		t.Errorf("round-trip: got %x, want %x", ctx.GetBytes(), expected)
	}
}

func TestBitcoinAttestationTrailingGarbage(t *testing.T) {
	// 0588960d73d71901 + 02 (payload len) + 00 (genesis) + ff (trailing garbage)
	data, _ := hex.DecodeString("0588960d73d71901" + "02" + "00" + "ff")
	dctx := core.NewBytesDeserializationContext(data)
	if _, err := core.DeserializeAttestation(dctx); err == nil {
		t.Error("expected TrailingGarbageError for bitcoin attestation with trailing garbage")
	}
}

func TestAttestationComparison(t *testing.T) {
	u1, _ := core.NewUnknownAttestation([]byte("unknown1"), []byte{})
	u2, _ := core.NewUnknownAttestation([]byte("unknown2"), []byte{})
	if !u1.Less(u2) {
		t.Error("UnknownAttestation(unknown1) should be < UnknownAttestation(unknown2)")
	}

	btc := &core.BitcoinBlockHeaderAttestation{Height: 1}
	pending := &core.PendingAttestation{URI: ""}
	if !btc.Less(pending) {
		t.Error("BitcoinBlockHeaderAttestation(1) should be < PendingAttestation(\"\")")
	}
}
