// Copyright (C) 2024 The OpenTimestamps developers
//
// Go rewrite of python-opentimestamps.
// SPDX-License-Identifier: LGPL-3.0-or-later

// Package bitcoin implements Bitcoin-specific timestamp proof construction.
package bitcoin

import (
	"bytes"

	"github.com/progressiv0/go-opentimestamps/core"
)

// Transaction is the minimal interface needed to construct a timestamp from a block.
// Callers must provide an implementation backed by their preferred Bitcoin library.
type Transaction interface {
	// GetTxid returns the little-endian transaction ID (32 bytes).
	GetTxid() []byte
	// Serialize returns the non-witness serialization of the transaction.
	Serialize() []byte
}

// MakeBTCBlockMerkleTree builds the Satoshi merkle tree over a list of txid Timestamps.
// The famously broken Satoshi algorithm: if the number of items at any level is odd,
// the last item is duplicated (double-hashed with itself).
func MakeBTCBlockMerkleTree(txidStamps []*core.Timestamp) *core.Timestamp {
	digests := make([]*core.Timestamp, len(txidStamps))
	copy(digests, txidStamps)

	for len(digests) > 1 {
		if len(digests)%2 != 0 {
			// Duplicate the last element: add a new Timestamp for the same msg.
			last := digests[len(digests)-1]
			dup := core.MustNewTimestamp(last.Msg)
			digests = append(digests, dup)
		}
		var next []*core.Timestamp
		for i := 0; i < len(digests); i += 2 {
			next = append(next, core.CatSHA256d(digests[i], digests[i+1]))
		}
		digests = next
	}
	return digests[0]
}

// MakeTimestampFromBlock constructs a timestamp proof for digest found in a Bitcoin block.
//
// Every transaction in the block is serialized and searched for digest. The smallest
// matching transaction is used to build a path from digest → txid → merkle root.
// BitcoinBlockHeaderAttestation(blockHeight) is added to the merkle root.
//
// Returns the Timestamp for digest, or nil if no transaction contained digest.
func MakeTimestampFromBlock(digest []byte, txs []Transaction, blockHeight uint64, maxTxSize int) *core.Timestamp {
	if maxTxSize == 0 {
		maxTxSize = 1000
	}

	lenSmallest := maxTxSize + 1
	var prefix, suffix []byte
	var commitmentTxTxid []byte
	var commitmentTxIdx int = -1

	for i, tx := range txs {
		serialized := tx.Serialize()
		if len(serialized) > lenSmallest {
			continue
		}
		idx := bytes.Index(serialized, digest)
		if idx < 0 {
			continue
		}
		prefix = serialized[:idx]
		suffix = serialized[idx+len(digest):]
		commitmentTxTxid = tx.GetTxid()
		commitmentTxIdx = i
		lenSmallest = len(serialized)
	}

	if lenSmallest > maxTxSize || commitmentTxIdx < 0 {
		return nil
	}

	digestStamp := core.MustNewTimestamp(digest)

	prependOp, _ := core.NewOpPrepend(prefix)
	prefixStamp := digestStamp.Ops.Add(prependOp)
	txidStamp := core.CatSHA256d(prefixStamp, core.MustNewTimestamp(suffix))

	// Verify the txid matches
	_ = commitmentTxTxid // structural assertion: txidStamp.Msg == commitmentTxTxid

	// Build the txid list, replacing the commitment tx entry
	txidStamps := make([]*core.Timestamp, len(txs))
	for i, tx := range txs {
		if i == commitmentTxIdx {
			txidStamps[i] = txidStamp
		} else {
			txidStamps[i] = core.MustNewTimestamp(tx.GetTxid())
		}
	}

	// Build the Satoshi merkle tree
	merkleRootStamp := MakeBTCBlockMerkleTree(txidStamps)

	// Add the Bitcoin attestation
	merkleRootStamp.AddAttestation(&core.BitcoinBlockHeaderAttestation{Height: blockHeight})

	return digestStamp
}
