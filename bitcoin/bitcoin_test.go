// Copyright (C) 2024 The OpenTimestamps developers
//
// Go rewrite of python-opentimestamps.
// SPDX-License-Identifier: LGPL-3.0-or-later

package bitcoin_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/progressiv0/go-opentimestamps/bitcoin"
	"github.com/progressiv0/go-opentimestamps/core"
)

// testTx is a minimal Transaction implementation for testing.
type testTx struct {
	txid []byte
	data []byte
}

func (t *testTx) GetTxid() []byte   { return t.txid }
func (t *testTx) Serialize() []byte { return t.data }

func sha256d(data []byte) []byte {
	h1 := sha256.Sum256(data)
	h2 := sha256.Sum256(h1[:])
	return h2[:]
}

func TestMakeBTCBlockMerkleTreeSingle(t *testing.T) {
	txid, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	stamps := []*core.Timestamp{core.MustNewTimestamp(txid)}
	root := bitcoin.MakeBTCBlockMerkleTree(stamps)
	if !bytes.Equal(root.Msg, txid) {
		t.Errorf("single tx merkle root: got %x, want %x", root.Msg, txid)
	}
}

func TestMakeBTCBlockMerkleTreeTwo(t *testing.T) {
	// With two transactions, merkle root = SHA256d(tx1 ‖ tx2)
	tx1, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	tx2, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000002")

	stamps := []*core.Timestamp{
		core.MustNewTimestamp(tx1),
		core.MustNewTimestamp(tx2),
	}
	root := bitcoin.MakeBTCBlockMerkleTree(stamps)

	// Expected: SHA256d(SHA256d(tx1 ‖ tx2)) — no, that's just SHA256d(tx1 ‖ tx2)
	// The Satoshi algorithm: hash pairs with SHA256d
	combined := append(tx1, tx2...)
	want := sha256d(combined)
	if !bytes.Equal(root.Msg, want) {
		t.Errorf("two-tx merkle root: got %x, want %x", root.Msg, want)
	}
}

func TestMakeBTCBlockMerkleTreeOdd(t *testing.T) {
	// Three transactions: the last is duplicated
	tx1, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	tx2, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000002")
	tx3, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000003")

	stamps := []*core.Timestamp{
		core.MustNewTimestamp(tx1),
		core.MustNewTimestamp(tx2),
		core.MustNewTimestamp(tx3),
	}
	root := bitcoin.MakeBTCBlockMerkleTree(stamps)

	// Level 0: tx1, tx2, tx3
	// Level 1: SHA256d(tx1‖tx2), SHA256d(tx3‖tx3) (tx3 duplicated)
	// Level 2: SHA256d(left1‖left2)
	left1 := sha256d(append(tx1, tx2...))
	left2 := sha256d(append(tx3, tx3...))
	want := sha256d(append(left1, left2...))
	if !bytes.Equal(root.Msg, want) {
		t.Errorf("three-tx merkle root: got %x, want %x", root.Msg, want)
	}
}

func TestMakeTimestampFromBlockFound(t *testing.T) {
	digest := []byte("commitment")
	txData := append([]byte("prefix-"), append(digest, []byte("-suffix")...)...)
	txid := sha256d(txData)

	txs := []bitcoin.Transaction{
		&testTx{txid: txid, data: txData},
	}

	ts := bitcoin.MakeTimestampFromBlock(digest, txs, 100, 0)
	if ts == nil {
		t.Fatal("expected non-nil timestamp")
	}
	if !bytes.Equal(ts.Msg, digest) {
		t.Errorf("timestamp msg: got %x, want %x", ts.Msg, digest)
	}

	// Check attestation is present on the merkle root
	pairs := ts.AllAttestations()
	found := false
	for _, p := range pairs {
		if btc, ok := p.Attestation.(*core.BitcoinBlockHeaderAttestation); ok {
			if btc.Height == 100 {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected BitcoinBlockHeaderAttestation(100)")
	}
}

func TestMakeTimestampFromBlockNotFound(t *testing.T) {
	digest := []byte("commitment")
	txData := []byte("unrelated data")
	txid := sha256d(txData)

	txs := []bitcoin.Transaction{
		&testTx{txid: txid, data: txData},
	}

	ts := bitcoin.MakeTimestampFromBlock(digest, txs, 100, 0)
	if ts != nil {
		t.Error("expected nil timestamp when digest not found")
	}
}
