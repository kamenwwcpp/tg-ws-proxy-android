package proto

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestMsgSplitter_AbridgedSmall(t *testing.T) {
	s := NewMsgSplitter(ProtoAbridgedInt)
	payloadWords := 5
	payloadLen := payloadWords * 4
	plain := make([]byte, 1+payloadLen)
	plain[0] = byte(payloadWords)
	for i := 1; i <= payloadLen; i++ {
		plain[i] = byte(i)
	}

	cipher := make([]byte, len(plain))
	for i := range plain {
		cipher[i] = plain[i] ^ 0xAA
	}

	parts := s.Split(cipher, plain)
	if len(parts) != 1 {
		t.Fatalf("expected 1 part, got %d", len(parts))
	}
	if !bytes.Equal(parts[0], cipher) {
		t.Fatalf("part does not match input cipher")
	}
}

func TestMsgSplitter_AbridgedLarge(t *testing.T) {
	s := NewMsgSplitter(ProtoAbridgedInt)
	payloadWords := 200
	payloadLen := payloadWords * 4
	plain := make([]byte, 4+payloadLen)
	plain[0] = 0x7F
	plain[1] = byte(payloadWords & 0xFF)
	plain[2] = byte((payloadWords >> 8) & 0xFF)
	plain[3] = byte((payloadWords >> 16) & 0xFF)

	cipher := make([]byte, len(plain))
	for i := range plain {
		cipher[i] = plain[i] ^ 0x55
	}

	parts := s.Split(cipher, plain)
	if len(parts) != 1 {
		t.Fatalf("expected 1 part, got %d", len(parts))
	}
	if !bytes.Equal(parts[0], cipher) {
		t.Fatalf("part does not match input cipher")
	}
}

func TestMsgSplitter_Intermediate(t *testing.T) {
	s := NewMsgSplitter(ProtoIntermediateInt)
	payloadLen := 64
	plain := make([]byte, 4+payloadLen)
	binary.LittleEndian.PutUint32(plain[0:4], uint32(payloadLen))

	cipher := make([]byte, len(plain))
	for i := range plain {
		cipher[i] = plain[i] ^ 0x33
	}

	// Split across two chunks
	p1 := s.Split(cipher[:20], plain[:20])
	if len(p1) != 0 {
		t.Fatalf("expected 0 parts for incomplete packet, got %d", len(p1))
	}

	p2 := s.Split(cipher[20:], plain[20:])
	if len(p2) != 1 {
		t.Fatalf("expected 1 part after completing packet, got %d", len(p2))
	}
	if !bytes.Equal(p2[0], cipher) {
		t.Fatalf("part does not match combined cipher")
	}
}

func TestMsgSplitter_MultiplePackets(t *testing.T) {
	s := NewMsgSplitter(ProtoAbridgedInt)

	// Packet 1: 4 words (16 bytes payload) + 1 byte header = 17 bytes
	p1 := make([]byte, 17)
	p1[0] = 4

	// Packet 2: 2 words (8 bytes payload) + 1 byte header = 9 bytes
	p2 := make([]byte, 9)
	p2[0] = 2

	combinedPlain := append(p1, p2...)
	combinedCipher := append(p1, p2...)

	parts := s.Split(combinedCipher, combinedPlain)
	if len(parts) != 2 {
		t.Fatalf("expected 2 parts, got %d", len(parts))
	}
	if len(parts[0]) != 17 || len(parts[1]) != 9 {
		t.Fatalf("incorrect packet sizes: %d, %d", len(parts[0]), len(parts[1]))
	}
}

func TestMsgSplitter_IncompleteAbridgedCompaction(t *testing.T) {
	s := NewMsgSplitter(ProtoAbridgedInt)

	// Incomplete packet: 10 words (40 bytes payload) + 1 byte header = 41 bytes
	pkt := make([]byte, 41)
	pkt[0] = 10
	for i := 1; i < len(pkt); i++ {
		pkt[i] = byte((i*7 + 13)%251 + 1)
	}

	// Send first 15 bytes
	p1 := s.Split(pkt[:15], pkt[:15])
	if len(p1) != 0 {
		t.Fatalf("expected 0 parts for partial, got %d", len(p1))
	}

	// Send remaining 26 bytes
	p2 := s.Split(pkt[15:], pkt[15:])
	if len(p2) != 1 {
		t.Fatalf("expected 1 part, got %d", len(p2))
	}
	if len(p2[0]) != 41 {
		t.Fatalf("expected 41 bytes, got %d", len(p2[0]))
	}
	if !bytes.Equal(p2[0], pkt) {
		t.Fatalf("compacted payload corrupted: got %x, want %x", p2[0], pkt)
	}
}

func TestUpstreamDomains(t *testing.T) {
	orig := GetCFDomains()
	defer SetCFDomains(orig)

	SetCFDomains([]string{"custom1.com", "custom2.com"})

	domains := AllUpstreamDomains(2, false, false)
	if len(domains) != 1 || domains[0] != "kws2.web.telegram.org" {
		t.Fatalf("unexpected direct domains: %v", domains)
	}

	domainsCF := AllUpstreamDomains(2, false, true)
	if len(domainsCF) != 3 {
		t.Fatalf("expected 3 domains with CF, got %d: %v", len(domainsCF), domainsCF)
	}

	domainsMedia := AllUpstreamDomains(4, true, false)
	if len(domainsMedia) != 2 {
		t.Fatalf("expected 2 media domains, got %d", len(domainsMedia))
	}
}
