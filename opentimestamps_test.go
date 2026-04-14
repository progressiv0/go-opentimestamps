// Copyright (C) 2024 The OpenTimestamps developers
//
// Go rewrite of python-opentimestamps.
// SPDX-License-Identifier: LGPL-3.0-or-later

package opentimestamps_test

import (
	"testing"

	"github.com/opentimestamps/go-opentimestamps"
	"github.com/opentimestamps/go-opentimestamps/core"
)

func TestNonceTimestamp(t *testing.T) {
	private := core.MustNewTimestamp([]byte("hello"))
	nonced, err := opentimestamps.NonceTimestamp(private, core.OpSHA256{}, 16)
	if err != nil {
		t.Fatal(err)
	}
	if len(nonced.Msg) != 32 {
		t.Errorf("nonced message length: got %d, want 32", len(nonced.Msg))
	}
	// The nonce stamp should be connected through the private timestamp's ops
	if private.Ops.Len() == 0 {
		t.Error("private timestamp should have ops after NonceTimestamp")
	}
}

func TestNonceTimestampUniqueness(t *testing.T) {
	private1 := core.MustNewTimestamp([]byte("hello"))
	private2 := core.MustNewTimestamp([]byte("hello"))

	n1, _ := opentimestamps.NonceTimestamp(private1, core.OpSHA256{}, 16)
	n2, _ := opentimestamps.NonceTimestamp(private2, core.OpSHA256{}, 16)

	// Two calls should produce different nonces (with overwhelming probability)
	if string(n1.Msg) == string(n2.Msg) {
		t.Error("two nonce timestamps should have different messages (random nonces)")
	}
}
