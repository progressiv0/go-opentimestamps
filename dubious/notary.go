// Copyright (C) 2024 The OpenTimestamps developers
//
// Go rewrite of python-opentimestamps.
// SPDX-License-Identifier: LGPL-3.0-or-later

// Package dubious contains attestation types whose long-term security is
// considered dubious. Currently this includes Ethereum, whose consensus model
// has changed repeatedly.
package dubious

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/progressiv0/go-opentimestamps/core"
)

// EthereumAttestationTag is the 8-byte tag for EthereumBlockHeaderAttestation.
var EthereumAttestationTag, _ = hex.DecodeString("30fe8087b5c7ead7")

// EthereumBlockHeaderAttestation is an Ethereum blockchain attestation.
// It lives in the "dubious" package because Ethereum's consensus model has
// changed repeatedly and its long-term security is uncertain.
type EthereumBlockHeaderAttestation struct {
	Height uint64
}

func (a *EthereumBlockHeaderAttestation) TagBytes() []byte { return EthereumAttestationTag }

func (a *EthereumBlockHeaderAttestation) Equal(other core.TimeAttestation) bool {
	o, ok := other.(*EthereumBlockHeaderAttestation)
	return ok && a.Height == o.Height
}

func (a *EthereumBlockHeaderAttestation) Less(other core.TimeAttestation) bool {
	if o, ok := other.(*EthereumBlockHeaderAttestation); ok {
		return a.Height < o.Height
	}
	return bytes.Compare(a.TagBytes(), other.TagBytes()) < 0
}

func (a *EthereumBlockHeaderAttestation) String() string {
	return fmt.Sprintf("EthereumBlockHeaderAttestation(%d)", a.Height)
}

func (a *EthereumBlockHeaderAttestation) Serialize(ctx core.SerializationContext) error {
	if err := ctx.WriteBytes(EthereumAttestationTag); err != nil {
		return err
	}
	payCtx := core.NewBytesSerializationContext()
	if err := payCtx.WriteVarUint(a.Height); err != nil {
		return err
	}
	return ctx.WriteVarBytes(payCtx.GetBytes())
}

// DeserializeAttestation reads a TimeAttestation, recognizing the Ethereum tag
// in addition to all core attestation types.
func DeserializeAttestation(ctx core.DeserializationContext) (core.TimeAttestation, error) {
	tag, err := ctx.ReadBytes(core.AttestationTagSize)
	if err != nil {
		return nil, err
	}

	serializedPayload, err := ctx.ReadVarBytes(core.MaxAttestationPayload)
	if err != nil {
		return nil, err
	}

	if bytes.Equal(tag, EthereumAttestationTag) {
		payCtx := core.NewBytesDeserializationContext(serializedPayload)
		height, err := payCtx.ReadVarUint()
		if err != nil {
			return nil, err
		}
		if err := payCtx.AssertEOF(); err != nil {
			return nil, err
		}
		return &EthereumBlockHeaderAttestation{Height: height}, nil
	}

	// Delegate to core for known types; reconstruct context
	fullCtx := core.NewBytesDeserializationContext(
		append(tag, prependVarBytes(serializedPayload)...),
	)
	return core.DeserializeAttestation(fullCtx)
}

// prependVarBytes encodes len as LEB128 and prepends it to data.
func prependVarBytes(data []byte) []byte {
	ctx := core.NewBytesSerializationContext()
	_ = ctx.WriteVarUint(uint64(len(data)))
	return append(ctx.GetBytes(), data...)
}
