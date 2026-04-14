// Copyright (C) 2024 The OpenTimestamps developers
//
// Go rewrite of python-opentimestamps.
// SPDX-License-Identifier: LGPL-3.0-or-later

package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
)

// GitTreeTimestamper provides efficient, privacy-preserving git tree timestamping.
//
// The Python implementation uses the `git` and `dbm` libraries and requires
// access to git repository objects. In Go, a full port would require
// github.com/go-git/go-git or equivalent. This file provides the core
// deterministic algorithms so they can be used by higher-level packages.
//
// The consensus-critical operations are:
//  1. hash_file: SHA-256 of blob data
//  2. deterministically_nonce_stamp: nonce_key + per-item nonce via tree_hash_op
//  3. make_merkle_tree: MakeMerkleTree with CatSHA256

// DeterministicallyNonceStamp adds a deterministic nonce to stamp,
// using treeHashOp and nonceKey. This is the consensus-critical
// function from GitTreeTimestamper.__init__.
func DeterministicallyNonceStamp(stamp *Timestamp, nonceKey []byte, treeHashOp CryptOpInterface) *Timestamp {
	nonce1, _ := treeHashOp.Apply(append(stamp.Msg, nonceKey...))
	nonce2, _ := treeHashOp.Apply(nonce1)

	var nonceAdded *Timestamp
	if nonce1[0]&0b1 == 0 {
		appendOp, _ := NewOpAppend(nonce2)
		nonceAdded = stamp.Ops.Add(appendOp)
	} else {
		prependOp, _ := NewOpPrepend(nonce2)
		nonceAdded = stamp.Ops.Add(prependOp)
	}
	return nonceAdded.Ops.Add(treeHashOp)
}

// ComputeNonceKey computes the nonce_key for a list of message digests,
// using the magic suffix b'\x01\x89\x08\x0c\xfb\xd0\xe8\x08'.
func ComputeNonceKey(msgs [][]byte, treeHashOp CryptOpInterface) ([]byte, error) {
	magic := []byte{0x01, 0x89, 0x08, 0x0c, 0xfb, 0xd0, 0xe8, 0x08}
	var buf bytes.Buffer
	for _, m := range msgs {
		buf.Write(m)
	}
	buf.Write(magic)
	return treeHashOp.HashReader(bytes.NewReader(buf.Bytes()))
}

// --- SHA-256 git object hashing helpers ---

// GitSHA256BlobHash computes SHA-256 of blob data (same as OpSHA256 applied to raw bytes).
func GitSHA256BlobHash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// GitSHA256BlobHashReader computes SHA-256 of data from a reader.
func GitSHA256BlobHashReader(r io.Reader) ([]byte, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// HexSHAToBin converts a 40-character hex SHA to 20 bytes, or a 64-character hex SHA to 32 bytes.
func HexSHAToBin(hexSHA string) ([]byte, error) {
	return hex.DecodeString(hexSHA)
}
