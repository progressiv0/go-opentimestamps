// Copyright (C) 2024 The OpenTimestamps developers
//
// Go rewrite of python-opentimestamps.
// SPDX-License-Identifier: LGPL-3.0-or-later

package core

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

const (
	AttestationTagSize    = 8
	MaxAttestationPayload = 8192
	MaxPendingURILength   = 1000
)

// VerificationError is returned when an attestation cannot be verified.
type VerificationError struct{ msg string }

func (e *VerificationError) Error() string { return e.msg }

// TimeAttestation is a time-attesting signature.
type TimeAttestation interface {
	TagBytes() []byte
	Equal(other TimeAttestation) bool
	Less(other TimeAttestation) bool
	Serialize(ctx SerializationContext) error
	String() string
}

// serializeAttestation serializes the tag + varbytes payload using the given payload writer.
func serializeAttestation(ctx SerializationContext, tag []byte, writePayload func(SerializationContext) error) error {
	if err := ctx.WriteBytes(tag); err != nil {
		return err
	}
	payCtx := NewBytesSerializationContext()
	if err := writePayload(payCtx); err != nil {
		return err
	}
	return ctx.WriteVarBytes(payCtx.GetBytes())
}

// --- PendingAttestation ---

// allowedURIBytes contains the characters allowed in Pending attestation URIs.
var allowedURIBytes = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/:")

// PendingAttestationTag is the 8-byte tag for PendingAttestation.
var PendingAttestationTag, _ = hex.DecodeString("83dfe30d2ef90c8e")

// PendingAttestation records a calendar URI that will supply a future proof.
type PendingAttestation struct {
	URI string
}

func checkPendingURI(uri []byte) error {
	if len(uri) > MaxPendingURILength {
		return fmt.Errorf("URI exceeds maximum length")
	}
	for _, c := range uri {
		if !bytes.ContainsRune(allowedURIBytes, rune(c)) {
			return fmt.Errorf("URI contains invalid character %q", c)
		}
	}
	return nil
}

func (a *PendingAttestation) TagBytes() []byte { return PendingAttestationTag }

func (a *PendingAttestation) Equal(other TimeAttestation) bool {
	o, ok := other.(*PendingAttestation)
	return ok && a.URI == o.URI
}

func (a *PendingAttestation) Less(other TimeAttestation) bool {
	if o, ok := other.(*PendingAttestation); ok {
		return a.URI < o.URI
	}
	return bytes.Compare(a.TagBytes(), other.TagBytes()) < 0
}

func (a *PendingAttestation) String() string { return fmt.Sprintf("PendingAttestation(%q)", a.URI) }

func (a *PendingAttestation) Serialize(ctx SerializationContext) error {
	return serializeAttestation(ctx, PendingAttestationTag, func(c SerializationContext) error {
		return c.WriteVarBytes([]byte(a.URI))
	})
}

// --- BitcoinBlockHeaderAttestation ---

// BitcoinAttestationTag is the 8-byte tag for BitcoinBlockHeaderAttestation.
var BitcoinAttestationTag, _ = hex.DecodeString("0588960d73d71901")

// BitcoinBlockHeaderAttestation is a Bitcoin blockchain attestation.
type BitcoinBlockHeaderAttestation struct {
	Height uint64
}

func (a *BitcoinBlockHeaderAttestation) TagBytes() []byte { return BitcoinAttestationTag }

func (a *BitcoinBlockHeaderAttestation) Equal(other TimeAttestation) bool {
	o, ok := other.(*BitcoinBlockHeaderAttestation)
	return ok && a.Height == o.Height
}

func (a *BitcoinBlockHeaderAttestation) Less(other TimeAttestation) bool {
	if o, ok := other.(*BitcoinBlockHeaderAttestation); ok {
		return a.Height < o.Height
	}
	return bytes.Compare(a.TagBytes(), other.TagBytes()) < 0
}

func (a *BitcoinBlockHeaderAttestation) String() string {
	return fmt.Sprintf("BitcoinBlockHeaderAttestation(%d)", a.Height)
}

func (a *BitcoinBlockHeaderAttestation) Serialize(ctx SerializationContext) error {
	return serializeAttestation(ctx, BitcoinAttestationTag, func(c SerializationContext) error {
		return c.WriteVarUint(a.Height)
	})
}

// VerifyAgainstMerkleRoot verifies that digest (the timestamp message at this
// node) equals the block merkle root, and returns the block time.
// merkleRootLE must be the merkle root in little-endian byte order.
func (a *BitcoinBlockHeaderAttestation) VerifyAgainstMerkleRoot(digest, merkleRootLE []byte, blockTime uint32) (uint32, error) {
	if len(digest) != 32 {
		return 0, &VerificationError{msg: fmt.Sprintf("expected digest with length 32 bytes; got %d bytes", len(digest))}
	}
	if !bytes.Equal(digest, merkleRootLE) {
		return 0, &VerificationError{msg: "digest does not match merkle root"}
	}
	return blockTime, nil
}

// --- LitecoinBlockHeaderAttestation ---

// LitecoinAttestationTag is the 8-byte tag for LitecoinBlockHeaderAttestation.
var LitecoinAttestationTag, _ = hex.DecodeString("06869a0d73d71b45")

// LitecoinBlockHeaderAttestation is a Litecoin blockchain attestation.
type LitecoinBlockHeaderAttestation struct {
	Height uint64
}

func (a *LitecoinBlockHeaderAttestation) TagBytes() []byte { return LitecoinAttestationTag }

func (a *LitecoinBlockHeaderAttestation) Equal(other TimeAttestation) bool {
	o, ok := other.(*LitecoinBlockHeaderAttestation)
	return ok && a.Height == o.Height
}

func (a *LitecoinBlockHeaderAttestation) Less(other TimeAttestation) bool {
	if o, ok := other.(*LitecoinBlockHeaderAttestation); ok {
		return a.Height < o.Height
	}
	return bytes.Compare(a.TagBytes(), other.TagBytes()) < 0
}

func (a *LitecoinBlockHeaderAttestation) String() string {
	return fmt.Sprintf("LitecoinBlockHeaderAttestation(%d)", a.Height)
}

func (a *LitecoinBlockHeaderAttestation) Serialize(ctx SerializationContext) error {
	return serializeAttestation(ctx, LitecoinAttestationTag, func(c SerializationContext) error {
		return c.WriteVarUint(a.Height)
	})
}

// --- UnknownAttestation ---

// UnknownAttestation is a placeholder for unrecognised attestation types.
type UnknownAttestation struct {
	tag     []byte
	Payload []byte
}

// NewUnknownAttestation creates an UnknownAttestation.
func NewUnknownAttestation(tag, payload []byte) (*UnknownAttestation, error) {
	if len(tag) != AttestationTagSize {
		return nil, fmt.Errorf("tag must be exactly %d bytes; got %d", AttestationTagSize, len(tag))
	}
	if len(payload) > MaxAttestationPayload {
		return nil, fmt.Errorf("payload too long: %d > %d", len(payload), MaxAttestationPayload)
	}
	t := make([]byte, len(tag))
	copy(t, tag)
	p := make([]byte, len(payload))
	copy(p, payload)
	return &UnknownAttestation{tag: t, Payload: p}, nil
}

func (a *UnknownAttestation) TagBytes() []byte { return a.tag }

func (a *UnknownAttestation) Equal(other TimeAttestation) bool {
	o, ok := other.(*UnknownAttestation)
	return ok && bytes.Equal(a.tag, o.tag) && bytes.Equal(a.Payload, o.Payload)
}

func (a *UnknownAttestation) Less(other TimeAttestation) bool {
	o, ok := other.(*UnknownAttestation)
	if !ok {
		return bytes.Compare(a.tag, other.TagBytes()) < 0
	}
	if !bytes.Equal(a.tag, o.tag) {
		return bytes.Compare(a.tag, o.tag) < 0
	}
	return bytes.Compare(a.Payload, o.Payload) < 0
}

func (a *UnknownAttestation) String() string {
	return fmt.Sprintf("UnknownAttestation(%x, %x)", a.tag, a.Payload)
}

func (a *UnknownAttestation) Serialize(ctx SerializationContext) error {
	if err := ctx.WriteBytes(a.tag); err != nil {
		return err
	}
	// Write payload as varbytes (the raw payload, already the inner bytes)
	return ctx.WriteVarBytes(a.Payload)
}

// --- Deserialization ---

// DeserializeAttestation reads a TimeAttestation from ctx.
// The EthereumBlockHeaderAttestation tag (30fe8087b5c7ead7) is recognized and
// returns an UnknownAttestation to avoid importing the dubious package from core.
// Callers that want Ethereum support should use dubious.DeserializeAttestation.
func DeserializeAttestation(ctx DeserializationContext) (TimeAttestation, error) {
	tag, err := ctx.ReadBytes(AttestationTagSize)
	if err != nil {
		return nil, err
	}

	serializedPayload, err := ctx.ReadVarBytes(MaxAttestationPayload)
	if err != nil {
		return nil, err
	}

	payCtx := NewBytesDeserializationContext(serializedPayload)

	var att TimeAttestation
	switch {
	case bytes.Equal(tag, PendingAttestationTag):
		att, err = deserializePendingAttestation(payCtx)
	case bytes.Equal(tag, BitcoinAttestationTag):
		att, err = deserializeBitcoinAttestation(payCtx)
	case bytes.Equal(tag, LitecoinAttestationTag):
		att, err = deserializeLitecoinAttestation(payCtx)
	default:
		return &UnknownAttestation{tag: tag, Payload: serializedPayload}, nil
	}
	if err != nil {
		return nil, err
	}

	if err := payCtx.AssertEOF(); err != nil {
		return nil, err
	}
	return att, nil
}

func deserializePendingAttestation(ctx DeserializationContext) (*PendingAttestation, error) {
	uriBytes, err := ctx.ReadVarBytes(MaxPendingURILength)
	if err != nil {
		return nil, err
	}
	if err := checkPendingURI(uriBytes); err != nil {
		return nil, newDeserializationError("invalid URI: %s", err)
	}
	return &PendingAttestation{URI: string(uriBytes)}, nil
}

func deserializeBitcoinAttestation(ctx DeserializationContext) (*BitcoinBlockHeaderAttestation, error) {
	height, err := ctx.ReadVarUint()
	if err != nil {
		return nil, err
	}
	return &BitcoinBlockHeaderAttestation{Height: height}, nil
}

func deserializeLitecoinAttestation(ctx DeserializationContext) (*LitecoinBlockHeaderAttestation, error) {
	height, err := ctx.ReadVarUint()
	if err != nil {
		return nil, err
	}
	return &LitecoinBlockHeaderAttestation{Height: height}, nil
}
