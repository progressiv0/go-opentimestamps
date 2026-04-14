// Copyright (C) 2024 The OpenTimestamps developers
//
// Go rewrite of python-opentimestamps.
// SPDX-License-Identifier: LGPL-3.0-or-later

package core_test

import (
	"bytes"
	"testing"

	"github.com/opentimestamps/go-opentimestamps/core"
)

func writeAndRead(t *testing.T, writes [][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	pw := core.NewPacketWriter(&buf)
	for _, w := range writes {
		if _, err := pw.Write(w); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := pw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return buf.Bytes()
}

func TestPacketWriterOpenClose(t *testing.T) {
	got := writeAndRead(t, nil)
	if !bytes.Equal(got, []byte{0x00}) {
		t.Errorf("empty packet: got %x, want 00", got)
	}
}

func TestPacketWriterEmpty(t *testing.T) {
	got := writeAndRead(t, [][]byte{{}})
	if !bytes.Equal(got, []byte{0x00}) {
		t.Errorf("empty write: got %x, want 00", got)
	}
}

func TestPacketWriterSubBlock(t *testing.T) {
	cases := []struct {
		writes   [][]byte
		expected []byte
	}{
		{[][]byte{[]byte("a")}, []byte{0x01, 'a', 0x00}},
		{[][]byte{[]byte("a"), []byte("b")}, []byte{0x02, 'a', 'b', 0x00}},
		{[][]byte{bytes.Repeat([]byte("x"), 254), []byte("x")}, append([]byte{0xff}, append(bytes.Repeat([]byte("x"), 255), 0x00)...)},
		{[][]byte{bytes.Repeat([]byte("x"), 255)}, append([]byte{0xff}, append(bytes.Repeat([]byte("x"), 255), 0x00)...)},
	}
	for i, tc := range cases {
		got := writeAndRead(t, tc.writes)
		if !bytes.Equal(got, tc.expected) {
			t.Errorf("case %d: got %x, want %x", i, got, tc.expected)
		}
	}
}

func TestPacketWriterMultiSubBlock(t *testing.T) {
	// 255+1 bytes → ff+255x + 01x + 00
	expected := append([]byte{0xff}, append(bytes.Repeat([]byte("x"), 255), 0x01, 'x', 0x00)...)
	got := writeAndRead(t, [][]byte{bytes.Repeat([]byte("x"), 256)})
	if !bytes.Equal(got, expected) {
		t.Errorf("256 bytes: got %x, want %x", got, expected)
	}
}

func TestPacketWriterFlush(t *testing.T) {
	var buf bytes.Buffer
	pw := core.NewPacketWriter(&buf)
	pw.Write([]byte("Hello"))
	pw.FlushPending()
	pw.Write([]byte("World!"))
	pw.Close()

	expected := []byte{0x05, 'H', 'e', 'l', 'l', 'o', 0x06, 'W', 'o', 'r', 'l', 'd', '!', 0x00}
	if !bytes.Equal(buf.Bytes(), expected) {
		t.Errorf("flush: got %x, want %x", buf.Bytes(), expected)
	}
}

func TestPacketReaderMissing(t *testing.T) {
	r := bytes.NewReader(nil)
	if _, err := core.NewPacketReader(r); err == nil {
		t.Error("expected PacketMissingError")
	}
}

func TestPacketReaderEmpty(t *testing.T) {
	r := bytes.NewReader([]byte{0x00})
	pr, err := core.NewPacketReader(r)
	if err != nil {
		t.Fatal(err)
	}
	data, err := pr.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Errorf("empty packet: got %x, want empty", data)
	}
}

func TestPacketReaderSingleSubPacket(t *testing.T) {
	raw := append([]byte{0x0c}, append([]byte("Hello World!"), 0x00)...)
	r := bytes.NewReader(raw)
	pr, err := core.NewPacketReader(r)
	if err != nil {
		t.Fatal(err)
	}
	data, err := pr.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte("Hello World!")) {
		t.Errorf("got %q, want %q", data, "Hello World!")
	}
}

func TestPacketReaderMultiSubPacket(t *testing.T) {
	raw := []byte{0x01, 'H', 0x0b, 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!', 0x00}
	r := bytes.NewReader(raw)
	pr, err := core.NewPacketReader(r)
	if err != nil {
		t.Fatal(err)
	}
	data, err := pr.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte("Hello World!")) {
		t.Errorf("got %q, want %q", data, "Hello World!")
	}
}

func TestPacketReaderTruncated(t *testing.T) {
	// Sub-packet length says 1, but there are no bytes
	r := bytes.NewReader([]byte{0x01})
	pr, err := core.NewPacketReader(r)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := pr.ReadAll()
	if len(data) != 0 {
		t.Errorf("truncated packet: got %x, want empty", data)
	}
	if pr.Truncated == 0 {
		t.Error("expected Truncated > 0")
	}
}

func TestPacketRoundTrip(t *testing.T) {
	messages := [][]byte{
		[]byte("hello"),
		bytes.Repeat([]byte("x"), 255),
		bytes.Repeat([]byte("y"), 256),
		bytes.Repeat([]byte("z"), 510),
	}
	for _, msg := range messages {
		var buf bytes.Buffer
		pw := core.NewPacketWriter(&buf)
		pw.Write(msg)
		pw.Close()

		pr, err := core.NewPacketReader(bytes.NewReader(buf.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		got, err := pr.ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, msg) {
			t.Errorf("round trip failed for %d-byte message", len(msg))
		}
	}
}
