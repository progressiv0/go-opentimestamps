// Copyright (C) 2024 The OpenTimestamps developers
//
// Go rewrite of python-opentimestamps.
// SPDX-License-Identifier: LGPL-3.0-or-later

// Package opentimestamps provides convenience functions for creating timestamps.
package opentimestamps

import (
	"crypto/rand"

	"github.com/opentimestamps/go-opentimestamps/core"
)

// NonceTimestamp creates a nonced version of a timestamp for privacy.
// A random nonce of the given length (default 16 bytes) is appended to the
// private timestamp's message, then cryptOp is applied.
func NonceTimestamp(privateTimestamp *core.Timestamp, cryptOp core.CryptOpInterface, length int) (*core.Timestamp, error) {
	if length <= 0 {
		length = 16
	}
	if cryptOp == nil {
		cryptOp = core.OpSHA256{}
	}
	nonce := make([]byte, length)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	appendOp, err := core.NewOpAppend(nonce)
	if err != nil {
		return nil, err
	}
	stamp2 := privateTimestamp.Ops.Add(appendOp)
	return stamp2.Ops.Add(cryptOp), nil
}
