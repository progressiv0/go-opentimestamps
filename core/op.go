// Copyright (C) 2024 The OpenTimestamps developers
//
// Go rewrite of python-opentimestamps.
// SPDX-License-Identifier: LGPL-3.0-or-later

package core

import (
	"bytes"
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/ripemd160"
)

const (
	MaxMsgLength    = 4096
	MaxResultLength = 4096

	TagSHA1      = 0x02
	TagRIPEMD160 = 0x03
	TagSHA256    = 0x08
	TagKECCAK256 = 0x67
	TagAppend    = 0xf0
	TagPrepend   = 0xf1
	TagReverse   = 0xf2
	TagHexlify   = 0xf3
)

// Op is a timestamp proof operation: an edge in the timestamp tree.
type Op interface {
	Tag() byte
	Apply(msg []byte) ([]byte, error)
	Serialize(ctx SerializationContext) error
	// Arg returns the binary argument for BinaryOps; nil for unary ops.
	Arg() []byte
	Equal(other Op) bool
	Less(other Op) bool
	String() string
}

// CryptOpInterface is a cryptographic Op that can also hash a stream.
type CryptOpInterface interface {
	Op
	DigestLength() int
	HashLibName() string
	HashReader(r io.Reader) ([]byte, error)
}

// --- Unary ops ---

// OpSHA1 applies SHA-1 to the message.
type OpSHA1 struct{}

func (o OpSHA1) Tag() byte { return TagSHA1 }
func (o OpSHA1) Arg() []byte { return nil }
func (o OpSHA1) DigestLength() int { return 20 }
func (o OpSHA1) HashLibName() string { return "sha1" }
func (o OpSHA1) String() string { return "sha1" }
func (o OpSHA1) Equal(other Op) bool { _, ok := other.(OpSHA1); return ok }
func (o OpSHA1) Less(other Op) bool   { return TagSHA1 < other.Tag() }

func (o OpSHA1) Apply(msg []byte) ([]byte, error) {
	if len(msg) > MaxMsgLength {
		return nil, fmt.Errorf("message too long: %d > %d", len(msg), MaxMsgLength)
	}
	h := sha1.New() //nolint:gosec
	h.Write(msg)
	return h.Sum(nil), nil
}

func (o OpSHA1) HashReader(r io.Reader) ([]byte, error) {
	h := sha1.New() //nolint:gosec
	if _, err := io.Copy(h, r); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func (o OpSHA1) Serialize(ctx SerializationContext) error { return ctx.WriteUint8(TagSHA1) }

// OpRIPEMD160 applies RIPEMD-160 to the message.
type OpRIPEMD160 struct{}

func (o OpRIPEMD160) Tag() byte { return TagRIPEMD160 }
func (o OpRIPEMD160) Arg() []byte { return nil }
func (o OpRIPEMD160) DigestLength() int { return 20 }
func (o OpRIPEMD160) HashLibName() string { return "ripemd160" }
func (o OpRIPEMD160) String() string { return "ripemd160" }
func (o OpRIPEMD160) Equal(other Op) bool { _, ok := other.(OpRIPEMD160); return ok }
func (o OpRIPEMD160) Less(other Op) bool   { return TagRIPEMD160 < other.Tag() }

func (o OpRIPEMD160) Apply(msg []byte) ([]byte, error) {
	if len(msg) > MaxMsgLength {
		return nil, fmt.Errorf("message too long: %d > %d", len(msg), MaxMsgLength)
	}
	h := ripemd160.New()
	h.Write(msg)
	return h.Sum(nil), nil
}

func (o OpRIPEMD160) HashReader(r io.Reader) ([]byte, error) {
	h := ripemd160.New()
	if _, err := io.Copy(h, r); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func (o OpRIPEMD160) Serialize(ctx SerializationContext) error { return ctx.WriteUint8(TagRIPEMD160) }

// OpSHA256 applies SHA-256 to the message.
type OpSHA256 struct{}

func (o OpSHA256) Tag() byte { return TagSHA256 }
func (o OpSHA256) Arg() []byte { return nil }
func (o OpSHA256) DigestLength() int { return 32 }
func (o OpSHA256) HashLibName() string { return "sha256" }
func (o OpSHA256) String() string { return "sha256" }
func (o OpSHA256) Equal(other Op) bool { _, ok := other.(OpSHA256); return ok }
func (o OpSHA256) Less(other Op) bool   { return TagSHA256 < other.Tag() }

func (o OpSHA256) Apply(msg []byte) ([]byte, error) {
	if len(msg) > MaxMsgLength {
		return nil, fmt.Errorf("message too long: %d > %d", len(msg), MaxMsgLength)
	}
	h := sha256.Sum256(msg)
	return h[:], nil
}

func (o OpSHA256) HashReader(r io.Reader) ([]byte, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func (o OpSHA256) Serialize(ctx SerializationContext) error { return ctx.WriteUint8(TagSHA256) }

// OpKECCAK256 applies Keccak-256 to the message.
type OpKECCAK256 struct{}

func (o OpKECCAK256) Tag() byte { return TagKECCAK256 }
func (o OpKECCAK256) Arg() []byte { return nil }
func (o OpKECCAK256) DigestLength() int { return 32 }
func (o OpKECCAK256) HashLibName() string { return "keccak256" }
func (o OpKECCAK256) String() string { return "keccak256" }
func (o OpKECCAK256) Equal(other Op) bool { _, ok := other.(OpKECCAK256); return ok }
func (o OpKECCAK256) Less(other Op) bool   { return TagKECCAK256 < other.Tag() }

func (o OpKECCAK256) Apply(msg []byte) ([]byte, error) {
	if len(msg) > MaxMsgLength {
		return nil, fmt.Errorf("message too long: %d > %d", len(msg), MaxMsgLength)
	}
	return keccak256(msg), nil
}

func (o OpKECCAK256) HashReader(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return keccak256(data), nil
}

func (o OpKECCAK256) Serialize(ctx SerializationContext) error { return ctx.WriteUint8(TagKECCAK256) }

// OpReverse reverses the message bytes (deprecated but supported for compatibility).
type OpReverse struct{}

func (o OpReverse) Tag() byte { return TagReverse }
func (o OpReverse) Arg() []byte { return nil }
func (o OpReverse) String() string { return "reverse" }
func (o OpReverse) Equal(other Op) bool { _, ok := other.(OpReverse); return ok }
func (o OpReverse) Less(other Op) bool   { return TagReverse < other.Tag() }

func (o OpReverse) Apply(msg []byte) ([]byte, error) {
	if len(msg) == 0 {
		return nil, fmt.Errorf("can't reverse an empty message")
	}
	result := make([]byte, len(msg))
	for i, b := range msg {
		result[len(msg)-1-i] = b
	}
	return result, nil
}

func (o OpReverse) Serialize(ctx SerializationContext) error { return ctx.WriteUint8(TagReverse) }

// OpHexlify converts the message to its lowercase hexadecimal representation.
type OpHexlify struct{}

func (o OpHexlify) Tag() byte { return TagHexlify }
func (o OpHexlify) Arg() []byte { return nil }
func (o OpHexlify) String() string { return "hexlify" }
func (o OpHexlify) Equal(other Op) bool { _, ok := other.(OpHexlify); return ok }
func (o OpHexlify) Less(other Op) bool   { return TagHexlify < other.Tag() }

func (o OpHexlify) Apply(msg []byte) ([]byte, error) {
	if len(msg) == 0 {
		return nil, fmt.Errorf("can't hexlify an empty message")
	}
	if len(msg) > MaxResultLength/2 {
		return nil, fmt.Errorf("message too long for hexlify: %d > %d", len(msg), MaxResultLength/2)
	}
	return []byte(hex.EncodeToString(msg)), nil
}

func (o OpHexlify) Serialize(ctx SerializationContext) error { return ctx.WriteUint8(TagHexlify) }

// --- Binary ops ---

// OpAppend appends a suffix to the message.
type OpAppend struct{ arg []byte }

// NewOpAppend creates an OpAppend with the given argument.
func NewOpAppend(arg []byte) (OpAppend, error) {
	if len(arg) == 0 {
		return OpAppend{}, fmt.Errorf("OpAppend arg can't be empty")
	}
	if len(arg) > MaxResultLength {
		return OpAppend{}, fmt.Errorf("OpAppend arg too long: %d > %d", len(arg), MaxResultLength)
	}
	a := make([]byte, len(arg))
	copy(a, arg)
	return OpAppend{arg: a}, nil
}

func (o OpAppend) Tag() byte       { return TagAppend }
func (o OpAppend) Arg() []byte     { return o.arg }
func (o OpAppend) String() string  { return "append " + hex.EncodeToString(o.arg) }

func (o OpAppend) Equal(other Op) bool {
	oa, ok := other.(OpAppend)
	return ok && bytes.Equal(o.arg, oa.arg)
}

func (o OpAppend) Less(other Op) bool {
	if other.Tag() != TagAppend {
		return TagAppend < other.Tag()
	}
	oa := other.(OpAppend)
	return bytes.Compare(o.arg, oa.arg) < 0
}

func (o OpAppend) Apply(msg []byte) ([]byte, error) {
	if len(msg) > MaxMsgLength {
		return nil, fmt.Errorf("message too long: %d > %d", len(msg), MaxMsgLength)
	}
	result := append(append([]byte(nil), msg...), o.arg...)
	if len(result) > MaxResultLength {
		return nil, fmt.Errorf("result too long: %d > %d", len(result), MaxResultLength)
	}
	return result, nil
}

func (o OpAppend) Serialize(ctx SerializationContext) error {
	if err := ctx.WriteUint8(TagAppend); err != nil {
		return err
	}
	return ctx.WriteVarBytes(o.arg)
}

// OpPrepend prepends a prefix to the message.
type OpPrepend struct{ arg []byte }

// NewOpPrepend creates an OpPrepend with the given argument.
func NewOpPrepend(arg []byte) (OpPrepend, error) {
	if len(arg) == 0 {
		return OpPrepend{}, fmt.Errorf("OpPrepend arg can't be empty")
	}
	if len(arg) > MaxResultLength {
		return OpPrepend{}, fmt.Errorf("OpPrepend arg too long: %d > %d", len(arg), MaxResultLength)
	}
	a := make([]byte, len(arg))
	copy(a, arg)
	return OpPrepend{arg: a}, nil
}

func (o OpPrepend) Tag() byte       { return TagPrepend }
func (o OpPrepend) Arg() []byte     { return o.arg }
func (o OpPrepend) String() string  { return "prepend " + hex.EncodeToString(o.arg) }

func (o OpPrepend) Equal(other Op) bool {
	oa, ok := other.(OpPrepend)
	return ok && bytes.Equal(o.arg, oa.arg)
}

func (o OpPrepend) Less(other Op) bool {
	if other.Tag() != TagPrepend {
		return TagPrepend < other.Tag()
	}
	oa := other.(OpPrepend)
	return bytes.Compare(o.arg, oa.arg) < 0
}

func (o OpPrepend) Apply(msg []byte) ([]byte, error) {
	if len(msg) > MaxMsgLength {
		return nil, fmt.Errorf("message too long: %d > %d", len(msg), MaxMsgLength)
	}
	result := append(append([]byte(nil), o.arg...), msg...)
	if len(result) > MaxResultLength {
		return nil, fmt.Errorf("result too long: %d > %d", len(result), MaxResultLength)
	}
	return result, nil
}

func (o OpPrepend) Serialize(ctx SerializationContext) error {
	if err := ctx.WriteUint8(TagPrepend); err != nil {
		return err
	}
	return ctx.WriteVarBytes(o.arg)
}

// --- Deserialization ---

// DeserializeOpFromTag reads an Op given the already-read tag byte.
func DeserializeOpFromTag(ctx DeserializationContext, tag byte) (Op, error) {
	switch tag {
	case TagSHA1:
		return OpSHA1{}, nil
	case TagRIPEMD160:
		return OpRIPEMD160{}, nil
	case TagSHA256:
		return OpSHA256{}, nil
	case TagKECCAK256:
		return OpKECCAK256{}, nil
	case TagReverse:
		return OpReverse{}, nil
	case TagHexlify:
		return OpHexlify{}, nil
	case TagAppend:
		arg, err := ctx.ReadVarBytesMinMax(1, MaxResultLength)
		if err != nil {
			return nil, err
		}
		return OpAppend{arg: arg}, nil
	case TagPrepend:
		arg, err := ctx.ReadVarBytesMinMax(1, MaxResultLength)
		if err != nil {
			return nil, err
		}
		return OpPrepend{arg: arg}, nil
	default:
		return nil, newDeserializationError("unknown op tag 0x%02x", tag)
	}
}
