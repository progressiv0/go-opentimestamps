// Copyright (C) 2024 The OpenTimestamps developers
//
// Go rewrite of python-opentimestamps.
// SPDX-License-Identifier: LGPL-3.0-or-later

package core

import (
	"fmt"
	"io"
)

// PacketWriter writes an individual packet to an append-only stream.
//
// The framing is: data is split into sub-packets of at most 255 bytes.
// Full sub-packets are prefixed with 0xff. Partial sub-packets are prefixed
// with their length. The end of the packet is marked with 0x00.
//
// This ensures that truncated writes do not corrupt subsequent packets.
type PacketWriter struct {
	w       io.Writer
	pending []byte
	closed  bool
}

// NewPacketWriter creates a new PacketWriter writing to w.
func NewPacketWriter(w io.Writer) *PacketWriter {
	return &PacketWriter{w: w}
}

// Write buffers data and flushes complete 255-byte sub-packets.
func (pw *PacketWriter) Write(buf []byte) (int, error) {
	if pw.closed {
		return 0, fmt.Errorf("write to closed packet")
	}
	pw.pending = append(pw.pending, buf...)

	// Write complete 255-byte sub-packets
	for len(pw.pending) >= 255 {
		chunk := pw.pending[:255]
		if _, err := pw.w.Write(append([]byte{0xff}, chunk...)); err != nil {
			return 0, err
		}
		pw.pending = pw.pending[255:]
	}
	return len(buf), nil
}

// FlushPending writes any buffered data as a partial sub-packet.
// If there is no pending data, this is a no-op.
func (pw *PacketWriter) FlushPending() error {
	if pw.closed {
		return fmt.Errorf("flush of closed packet")
	}
	if len(pw.pending) == 0 {
		return nil
	}
	header := []byte{byte(len(pw.pending))}
	if _, err := pw.w.Write(append(header, pw.pending...)); err != nil {
		return err
	}
	pw.pending = nil
	return nil
}

// Close flushes any pending data and writes the 0x00 end-of-packet marker.
func (pw *PacketWriter) Close() error {
	if err := pw.FlushPending(); err != nil {
		return err
	}
	if _, err := pw.w.Write([]byte{0x00}); err != nil {
		return err
	}
	pw.closed = true
	return nil
}

// PacketMissingError is returned when a packet is completely absent.
type PacketMissingError struct{ msg string }

func (e *PacketMissingError) Error() string { return e.msg }

// PacketReader reads an individual packet from an append-only stream.
type PacketReader struct {
	r                   io.Reader
	lenRemainingSubpack int
	endOfPacket         bool
	// Truncated is non-zero if the packet was truncated; value is approximate missing bytes.
	Truncated int
}

// NewPacketReader creates a PacketReader reading from r.
// Reads the first length byte immediately; raises PacketMissingError if unavailable.
func NewPacketReader(r io.Reader) (*PacketReader, error) {
	pr := &PacketReader{r: r}
	buf := make([]byte, 1)
	n, err := r.Read(buf)
	if n == 0 || err == io.EOF {
		return nil, &PacketMissingError{msg: "packet completely missing"}
	}
	if err != nil {
		return nil, err
	}
	pr.lenRemainingSubpack = int(buf[0])
	if pr.lenRemainingSubpack == 0 {
		pr.endOfPacket = true
	}
	return pr, nil
}

// Read reads up to len(p) bytes from the packet.
func (pr *PacketReader) Read(p []byte) (int, error) {
	if pr.endOfPacket {
		return 0, io.EOF
	}

	total := 0
	remaining := len(p)
	for remaining > 0 && !pr.endOfPacket {
		if pr.lenRemainingSubpack > 0 {
			toRead := remaining
			if toRead > pr.lenRemainingSubpack {
				toRead = pr.lenRemainingSubpack
			}
			n, err := io.ReadFull(pr.r, p[total:total+toRead])
			total += n
			pr.lenRemainingSubpack -= n
			remaining -= n
			if err != nil {
				pr.Truncated = toRead - n + 1
				pr.endOfPacket = true
				return total, nil
			}
		} else {
			// Read next sub-packet length
			buf := make([]byte, 1)
			n, err := pr.r.Read(buf)
			if n == 0 || err == io.EOF {
				pr.Truncated = 1
				pr.endOfPacket = true
				return total, nil
			}
			if err != nil {
				return total, err
			}
			pr.lenRemainingSubpack = int(buf[0])
			if pr.lenRemainingSubpack == 0 {
				pr.endOfPacket = true
			}
		}
	}
	if pr.endOfPacket && total == 0 {
		return 0, io.EOF
	}
	return total, nil
}

// ReadAll reads the entire packet into a byte slice.
func (pr *PacketReader) ReadAll() ([]byte, error) {
	return io.ReadAll(pr)
}
