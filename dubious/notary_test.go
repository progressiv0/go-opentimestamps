// Copyright (C) 2024 The OpenTimestamps developers
//
// Go rewrite of python-opentimestamps.
// SPDX-License-Identifier: LGPL-3.0-or-later

package dubious_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/progressiv0/go-opentimestamps/core"
	"github.com/progressiv0/go-opentimestamps/dubious"
)

func TestEthereumAttestationSerialize(t *testing.T) {
	att := &dubious.EthereumBlockHeaderAttestation{Height: 0}
	expected, _ := hex.DecodeString("30fe8087b5c7ead7" + "01" + "00")

	ctx := core.NewBytesSerializationContext()
	if err := att.Serialize(ctx); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ctx.GetBytes(), expected) {
		t.Errorf("serialize: got %x, want %x", ctx.GetBytes(), expected)
	}

	dctx := core.NewBytesDeserializationContext(expected)
	att2, err := dubious.DeserializeAttestation(dctx)
	if err != nil {
		t.Fatal(err)
	}
	eth, ok := att2.(*dubious.EthereumBlockHeaderAttestation)
	if !ok {
		t.Fatalf("expected *EthereumBlockHeaderAttestation, got %T", att2)
	}
	if eth.Height != 0 {
		t.Errorf("height: got %d, want 0", eth.Height)
	}
}

func TestEthereumAttestationEquality(t *testing.T) {
	a1 := &dubious.EthereumBlockHeaderAttestation{Height: 42}
	a2 := &dubious.EthereumBlockHeaderAttestation{Height: 42}
	a3 := &dubious.EthereumBlockHeaderAttestation{Height: 43}

	if !a1.Equal(a2) {
		t.Error("attestations with same height should be equal")
	}
	if a1.Equal(a3) {
		t.Error("attestations with different heights should not be equal")
	}
}

func TestEthereumAttestationOrdering(t *testing.T) {
	a1 := &dubious.EthereumBlockHeaderAttestation{Height: 1}
	a2 := &dubious.EthereumBlockHeaderAttestation{Height: 2}
	if !a1.Less(a2) {
		t.Error("height 1 should be less than height 2")
	}
}
