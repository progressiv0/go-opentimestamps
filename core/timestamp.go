// Copyright (C) 2024 The OpenTimestamps developers
//
// Go rewrite of python-opentimestamps.
// SPDX-License-Identifier: LGPL-3.0-or-later

package core

import (
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Timestamp is a node in the timestamp proof tree. It records a message,
// the operations from that message to child messages, and attestations.
type Timestamp struct {
	Msg          []byte
	Attestations []TimeAttestation
	Ops          *OpSet
}

// NewTimestamp creates a new Timestamp for the given message.
func NewTimestamp(msg []byte) (*Timestamp, error) {
	if len(msg) > MaxMsgLength {
		return nil, fmt.Errorf("message exceeds Op length limit: %d > %d", len(msg), MaxMsgLength)
	}
	t := &Timestamp{Msg: msg}
	t.Ops = newOpSet(t)
	return t, nil
}

// MustNewTimestamp panics on error (for use in tests/known-safe calls).
func MustNewTimestamp(msg []byte) *Timestamp {
	t, err := NewTimestamp(msg)
	if err != nil {
		panic(err)
	}
	return t
}

// AddAttestation adds an attestation if not already present.
func (t *Timestamp) AddAttestation(a TimeAttestation) {
	for _, existing := range t.Attestations {
		if existing.Equal(a) {
			return
		}
	}
	t.Attestations = append(t.Attestations, a)
}

// HasAttestation checks whether a given attestation is present.
func (t *Timestamp) HasAttestation(a TimeAttestation) bool {
	for _, existing := range t.Attestations {
		if existing.Equal(a) {
			return true
		}
	}
	return false
}

// RemoveAttestation removes the first attestation equal to a.
func (t *Timestamp) RemoveAttestation(a TimeAttestation) bool {
	for i, existing := range t.Attestations {
		if existing.Equal(a) {
			t.Attestations = append(t.Attestations[:i], t.Attestations[i+1:]...)
			return true
		}
	}
	return false
}

// Merge incorporates all operations and attestations from other into t.
func (t *Timestamp) Merge(other *Timestamp) error {
	if hex.EncodeToString(t.Msg) != hex.EncodeToString(other.Msg) {
		return fmt.Errorf("can't merge timestamps for different messages")
	}
	for _, a := range other.Attestations {
		t.AddAttestation(a)
	}
	for _, entry := range other.Ops.entries {
		existing := t.Ops.Add(entry.Op)
		if err := existing.Merge(entry.Stamp); err != nil {
			return err
		}
	}
	return nil
}

// AttestationPair is a (msg, attestation) pair.
type AttestationPair struct {
	Msg         []byte
	Attestation TimeAttestation
}

// AllAttestations recursively collects all (msg, attestation) pairs.
func (t *Timestamp) AllAttestations() []AttestationPair {
	var results []AttestationPair
	for _, a := range t.Attestations {
		results = append(results, AttestationPair{Msg: t.Msg, Attestation: a})
	}
	for _, entry := range t.Ops.entries {
		results = append(results, entry.Stamp.AllAttestations()...)
	}
	return results
}

// Equal compares two timestamps for equality.
func (t *Timestamp) Equal(other *Timestamp) bool {
	if hex.EncodeToString(t.Msg) != hex.EncodeToString(other.Msg) {
		return false
	}
	if len(t.Attestations) != len(other.Attestations) {
		return false
	}
	for _, a := range t.Attestations {
		if !other.HasAttestation(a) {
			return false
		}
	}
	if len(t.Ops.entries) != len(other.Ops.entries) {
		return false
	}
	for _, e := range t.Ops.entries {
		found := false
		for _, oe := range other.Ops.entries {
			if e.Op.Equal(oe.Op) && e.Stamp.Equal(oe.Stamp) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Serialize writes the timestamp tree in the OTS binary format.
func (t *Timestamp) Serialize(ctx SerializationContext) error {
	if len(t.Attestations) == 0 && len(t.Ops.entries) == 0 {
		return fmt.Errorf("an empty timestamp can't be serialized")
	}

	sortedAtts := sortedAttestations(t.Attestations)

	if len(sortedAtts) > 1 {
		for _, a := range sortedAtts[:len(sortedAtts)-1] {
			if err := ctx.WriteBytes([]byte{0xff, 0x00}); err != nil {
				return err
			}
			if err := a.Serialize(ctx); err != nil {
				return err
			}
		}
	}

	if len(t.Ops.entries) == 0 {
		if err := ctx.WriteBytes([]byte{0x00}); err != nil {
			return err
		}
		return sortedAtts[len(sortedAtts)-1].Serialize(ctx)
	}

	if len(sortedAtts) > 0 {
		if err := ctx.WriteBytes([]byte{0xff, 0x00}); err != nil {
			return err
		}
		if err := sortedAtts[len(sortedAtts)-1].Serialize(ctx); err != nil {
			return err
		}
	}

	sortedOps := sortedOpEntries(t.Ops.entries)
	for _, e := range sortedOps[:len(sortedOps)-1] {
		if err := ctx.WriteBytes([]byte{0xff}); err != nil {
			return err
		}
		if err := e.Op.Serialize(ctx); err != nil {
			return err
		}
		if err := e.Stamp.Serialize(ctx); err != nil {
			return err
		}
	}

	last := sortedOps[len(sortedOps)-1]
	if err := last.Op.Serialize(ctx); err != nil {
		return err
	}
	return last.Stamp.Serialize(ctx)
}

// DeserializeTimestamp reads a Timestamp from ctx given the already-known initial message.
func DeserializeTimestamp(ctx DeserializationContext, initialMsg []byte, recursionLimit int) (*Timestamp, error) {
	if recursionLimit <= 0 {
		return nil, &RecursionLimitError{msg: "reached timestamp recursion depth limit while deserializing"}
	}

	t, err := NewTimestamp(initialMsg)
	if err != nil {
		return nil, err
	}

	processTagOrAttestation := func(tag byte) error {
		if tag == 0x00 {
			att, err := DeserializeAttestation(ctx)
			if err != nil {
				return err
			}
			t.AddAttestation(att)
			return nil
		}
		op, err := DeserializeOpFromTag(ctx, tag)
		if err != nil {
			return err
		}
		result, err := op.Apply(initialMsg)
		if err != nil {
			return newDeserializationError("invalid timestamp; message invalid for op %s: %s", op, err)
		}
		subStamp, err := DeserializeTimestamp(ctx, result, recursionLimit-1)
		if err != nil {
			return err
		}
		t.Ops.Set(op, subStamp)
		return nil
	}

	tag, err := ctx.ReadUint8()
	if err != nil {
		return nil, err
	}
	for tag == 0xff {
		next, err := ctx.ReadUint8()
		if err != nil {
			return nil, err
		}
		if err := processTagOrAttestation(next); err != nil {
			return nil, err
		}
		tag, err = ctx.ReadUint8()
		if err != nil {
			return nil, err
		}
	}
	if err := processTagOrAttestation(tag); err != nil {
		return nil, err
	}
	return t, nil
}

// StrTree returns a human-readable representation of the timestamp tree.
func (t *Timestamp) StrTree(indent, verbosity int) string {
	var sb strings.Builder

	for _, a := range sortedAttestations(t.Attestations) {
		sb.WriteString(strings.Repeat(" ", indent))
		sb.WriteString("verify ")
		sb.WriteString(a.String())
		switch a.(type) {
		case *BitcoinBlockHeaderAttestation:
			sb.WriteString("\n")
			sb.WriteString(strings.Repeat(" ", indent))
			sb.WriteString("# Bitcoin block merkle root ")
			sb.WriteString(hex.EncodeToString(reverseBytes(t.Msg)))
			sb.WriteString("\n")
		case *LitecoinBlockHeaderAttestation:
			sb.WriteString("\n")
			sb.WriteString(strings.Repeat(" ", indent))
			sb.WriteString("# Litecoin block merkle root ")
			sb.WriteString(hex.EncodeToString(reverseBytes(t.Msg)))
			sb.WriteString("\n")
		default:
			sb.WriteString("\n")
		}
	}

	sortedOps := sortedOpEntries(t.Ops.entries)

	if len(sortedOps) > 1 {
		for _, e := range sortedOps {
			sb.WriteString(strings.Repeat(" ", indent))
			sb.WriteString(" -> ")
			sb.WriteString(e.Op.String())
			if verbosity > 0 {
				if result, err := e.Op.Apply(t.Msg); err == nil {
					sb.WriteString(" == ")
					sb.WriteString(hex.EncodeToString(result))
				}
			}
			sb.WriteString("\n")
			sb.WriteString(e.Stamp.StrTree(indent+4, verbosity))
		}
	} else if len(sortedOps) == 1 {
		e := sortedOps[0]
		sb.WriteString(strings.Repeat(" ", indent))
		sb.WriteString(e.Op.String())
		if verbosity > 0 {
			if result, err := e.Op.Apply(t.Msg); err == nil {
				sb.WriteString(" == ")
				sb.WriteString(hex.EncodeToString(result))
			}
		}
		sb.WriteString("\n")
		sb.WriteString(e.Stamp.StrTree(indent, verbosity))
	}

	return sb.String()
}

func reverseBytes(b []byte) []byte {
	r := make([]byte, len(b))
	for i, v := range b {
		r[len(b)-1-i] = v
	}
	return r
}

// --- Merkle tree helpers ---

// CatSHA256 concatenates left and right, then SHA-256 hashes the result.
// Both left and right may be *Timestamp or []byte.
// The appropriate OpAppend/OpPrepend are added automatically.
// Returns the child Timestamp for sha256(left ‖ right).
func CatSHA256(left, right *Timestamp) *Timestamp {
	return catThenUnaryOp(OpSHA256{}, left, right)
}

// CatSHA256d applies SHA-256 twice (double-SHA256) to the concatenation.
func CatSHA256d(left, right *Timestamp) *Timestamp {
	sha256Stamp := CatSHA256(left, right)
	return sha256Stamp.Ops.Add(OpSHA256{})
}

// catThenUnaryOp implements cat_then_unary_op from Python.
func catThenUnaryOp(op CryptOpInterface, left, right *Timestamp) *Timestamp {
	appendArg, _ := NewOpAppend(right.Msg)
	prependArg, _ := NewOpPrepend(left.Msg)

	leftAppendStamp := left.Ops.Add(appendArg)
	rightPrependStamp := right.Ops.Add(prependArg)

	// Both must yield the same message; synchronize them.
	left.Ops.Set(appendArg, rightPrependStamp)
	_ = leftAppendStamp // replaced

	return rightPrependStamp.Ops.Add(op)
}

// MakeMerkleTree builds a merkle tree in-place using CatSHA256.
// Returns the root Timestamp.
// Panics if timestamps is empty.
func MakeMerkleTree(timestamps []*Timestamp) *Timestamp {
	return MakeMerkleTreeWithOp(timestamps, CatSHA256)
}

// MakeMerkleTreeWithOp builds a merkle tree using a custom binary operation.
func MakeMerkleTreeWithOp(timestamps []*Timestamp, binop func(left, right *Timestamp) *Timestamp) *Timestamp {
	stamps := make([]*Timestamp, len(timestamps))
	copy(stamps, timestamps)

	if len(stamps) == 0 {
		panic("need at least one timestamp")
	}

	for len(stamps) > 1 {
		var next []*Timestamp
		var prev *Timestamp
		for _, stamp := range stamps {
			if prev != nil {
				next = append(next, binop(prev, stamp))
				prev = nil
			} else {
				prev = stamp
			}
		}
		if prev != nil {
			next = append(next, prev)
		}
		stamps = next
	}
	return stamps[0]
}

// --- OpSet ---

// OpEntry is a (Op, Stamp) pair stored in an OpSet.
type OpEntry struct {
	Op    Op
	Stamp *Timestamp
}

// GetOp returns the operation.
func (e OpEntry) GetOp() Op { return e.Op }

// GetStamp returns the child timestamp.
func (e OpEntry) GetStamp() *Timestamp { return e.Stamp }

// OpSet is an ordered map from Op to child Timestamp.
type OpSet struct {
	entries []OpEntry
	parent  *Timestamp
}

func newOpSet(parent *Timestamp) *OpSet {
	return &OpSet{parent: parent}
}

// Add returns the child timestamp for op, creating it if it does not already exist.
func (s *OpSet) Add(op Op) *Timestamp {
	for _, e := range s.entries {
		if e.Op.Equal(op) {
			return e.Stamp
		}
	}
	result, err := op.Apply(s.parent.Msg)
	if err != nil {
		panic(fmt.Sprintf("op.Apply failed: %s", err))
	}
	child, err := NewTimestamp(result)
	if err != nil {
		panic(fmt.Sprintf("NewTimestamp failed: %s", err))
	}
	s.entries = append(s.entries, OpEntry{Op: op, Stamp: child})
	return child
}

// Set stores an existing child timestamp for op (used during deserialization / merging).
func (s *OpSet) Set(op Op, stamp *Timestamp) {
	for i, e := range s.entries {
		if e.Op.Equal(op) {
			s.entries[i].Stamp = stamp
			return
		}
	}
	s.entries = append(s.entries, OpEntry{Op: op, Stamp: stamp})
}

// Get returns the child timestamp for op, or nil.
func (s *OpSet) Get(op Op) *Timestamp {
	for _, e := range s.entries {
		if e.Op.Equal(op) {
			return e.Stamp
		}
	}
	return nil
}

// Len returns the number of entries.
func (s *OpSet) Len() int { return len(s.entries) }

// Entries returns a copy of the op entries.
func (s *OpSet) Entries() []OpEntry { return append([]OpEntry(nil), s.entries...) }

// Delete removes the entry for op.
func (s *OpSet) Delete(op Op) bool {
	for i, e := range s.entries {
		if e.Op.Equal(op) {
			s.entries = append(s.entries[:i], s.entries[i+1:]...)
			return true
		}
	}
	return false
}

func sortedAttestations(atts []TimeAttestation) []TimeAttestation {
	result := append([]TimeAttestation(nil), atts...)
	sort.Slice(result, func(i, j int) bool {
		return result[i].Less(result[j])
	})
	return result
}

func sortedOpEntries(entries []OpEntry) []OpEntry {
	result := append([]OpEntry(nil), entries...)
	sort.Slice(result, func(i, j int) bool {
		return result[i].Op.Less(result[j].Op)
	})
	return result
}

// --- DetachedTimestampFile ---

// HEADER_MAGIC is the 31-byte magic for .ots files.
var HEADER_MAGIC = []byte("\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94")

const (
	MinFileDigestLength = 20
	MaxFileDigestLength = 32
	MajorVersion        = 1
)

// DetachedTimestampFile represents a .ots timestamp file.
type DetachedTimestampFile struct {
	FileHashOp CryptOpInterface
	Timestamp  *Timestamp
}

// FileDigest returns the digest of the original file.
func (f *DetachedTimestampFile) FileDigest() []byte {
	return f.Timestamp.Msg
}

// NewDetachedTimestampFile creates a DetachedTimestampFile.
func NewDetachedTimestampFile(fileHashOp CryptOpInterface, timestamp *Timestamp) (*DetachedTimestampFile, error) {
	if len(timestamp.Msg) != fileHashOp.DigestLength() {
		return nil, fmt.Errorf("timestamp message length and file_hash_op digest length differ")
	}
	return &DetachedTimestampFile{FileHashOp: fileHashOp, Timestamp: timestamp}, nil
}

// DetachedTimestampFileFromReader hashes the contents of r and creates a DetachedTimestampFile.
func DetachedTimestampFileFromReader(fileHashOp CryptOpInterface, r io.Reader) (*DetachedTimestampFile, error) {
	digest, err := fileHashOp.HashReader(r)
	if err != nil {
		return nil, err
	}
	ts, err := NewTimestamp(digest)
	if err != nil {
		return nil, err
	}
	return &DetachedTimestampFile{FileHashOp: fileHashOp, Timestamp: ts}, nil
}

// Serialize writes the DetachedTimestampFile to ctx.
func (f *DetachedTimestampFile) Serialize(ctx SerializationContext) error {
	if err := ctx.WriteBytes(HEADER_MAGIC); err != nil {
		return err
	}
	if err := ctx.WriteUint8(MajorVersion); err != nil {
		return err
	}
	if err := f.FileHashOp.Serialize(ctx); err != nil {
		return err
	}
	if err := ctx.WriteBytes(f.Timestamp.Msg); err != nil {
		return err
	}
	return f.Timestamp.Serialize(ctx)
}

// DeserializeDetachedTimestampFile reads a DetachedTimestampFile from ctx.
func DeserializeDetachedTimestampFile(ctx DeserializationContext) (*DetachedTimestampFile, error) {
	if err := ctx.AssertMagic(HEADER_MAGIC); err != nil {
		return nil, err
	}
	major, err := ctx.ReadUint8()
	if err != nil {
		return nil, err
	}
	if int(major) != MajorVersion {
		return nil, &UnsupportedMajorVersion{Version: int(major)}
	}

	op, err := DeserializeCryptOp(ctx)
	if err != nil {
		return nil, err
	}

	fileHash, err := ctx.ReadBytes(op.DigestLength())
	if err != nil {
		return nil, err
	}

	ts, err := DeserializeTimestamp(ctx, fileHash, 256)
	if err != nil {
		return nil, err
	}

	if err := ctx.AssertEOF(); err != nil {
		return nil, err
	}

	return &DetachedTimestampFile{FileHashOp: op, Timestamp: ts}, nil
}

// DeserializeCryptOp reads a CryptOp (SHA1, RIPEMD160, or SHA256) from ctx.
func DeserializeCryptOp(ctx DeserializationContext) (CryptOpInterface, error) {
	tag, err := ctx.ReadUint8()
	if err != nil {
		return nil, err
	}
	switch tag {
	case TagSHA1:
		return OpSHA1{}, nil
	case TagRIPEMD160:
		return OpRIPEMD160{}, nil
	case TagSHA256:
		return OpSHA256{}, nil
	default:
		return nil, newDeserializationError("unknown crypt op tag 0x%02x", tag)
	}
}
