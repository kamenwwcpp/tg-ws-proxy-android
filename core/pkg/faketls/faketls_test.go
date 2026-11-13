package faketls

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func generateSimulatedClientHello(secret []byte, ts time.Time) []byte {
	ch := make([]byte, 512)
	rand.Read(ch)

	// TLS Record Header
	ch[0] = TLSRecordHandshake
	ch[1] = 0x03
	ch[2] = 0x01
	binary.BigEndian.PutUint16(ch[3:5], uint16(len(ch)-5))

	// Handshake Header
	ch[5] = 0x01 // ClientHello
	ch[6] = 0x00
	binary.BigEndian.PutUint16(ch[7:9], uint16(len(ch)-9))
	ch[9] = 0x03
	ch[10] = 0x03 // TLS 1.2

	ch[43] = 0x20 // Session ID length 32

	// Zero out client random (offset 11..43)
	for i := 0; i < 32; i++ {
		ch[ClientRandomOffset+i] = 0
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(ch)
	expected := mac.Sum(nil)

	// Fill first 28 bytes
	copy(ch[ClientRandomOffset:ClientRandomOffset+28], expected[:28])

	// XOR timestamp with expected[28:32]
	var tsBytes [4]byte
	binary.LittleEndian.PutUint32(tsBytes[:], uint32(ts.Unix()))
	for i := 0; i < 4; i++ {
		ch[ClientRandomOffset+28+i] = tsBytes[i] ^ expected[28+i]
	}

	return ch
}

func TestVerifyClientHello_Valid(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	ch := generateSimulatedClientHello(secret, time.Now())

	info, err := VerifyClientHello(ch, secret)
	if err != nil {
		t.Fatalf("expected valid ClientHello, got err: %v", err)
	}
	if info == nil {
		t.Fatalf("expected info, got nil")
	}
	if len(info.SessionID) != 32 {
		t.Fatalf("expected 32-byte session ID")
	}
}

func TestVerifyClientHello_WrongSecret(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	wrongSecret := []byte("wrong_secret_1234567890123456789")
	ch := generateSimulatedClientHello(secret, time.Now())

	_, err := VerifyClientHello(ch, wrongSecret)
	if err == nil {
		t.Fatalf("expected error for wrong secret, got nil")
	}
}

func TestVerifyClientHello_ExpiredTimestamp(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	ch := generateSimulatedClientHello(secret, time.Now().Add(-10*time.Minute))

	_, err := VerifyClientHello(ch, secret)
	if err == nil {
		t.Fatalf("expected error for expired timestamp, got nil")
	}
}

func TestBuildServerHello(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	clientRandom := make([]byte, 32)
	sessionID := make([]byte, 32)
	rand.Read(clientRandom)
	rand.Read(sessionID)

	sh, err := BuildServerHello(secret, clientRandom, sessionID)
	if err != nil {
		t.Fatalf("BuildServerHello failed: %v", err)
	}

	if len(sh) < 100 {
		t.Fatalf("ServerHello too short: %d", len(sh))
	}
	if sh[0] != TLSRecordHandshake {
		t.Fatalf("invalid record type: %02x", sh[0])
	}
}

func TestFakeTLSConn_Pipe(t *testing.T) {
	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()

	tlsServer := NewFakeTLSConn(serverPipe)

	msg := []byte("Test Fake TLS stream tunneling")

	go func() {
		tlsServer.Write(msg)
	}()

	// The raw client pipe receives TLS record 0x17 0x03 0x03 [len] [msg]
	var hdr [5]byte
	io.ReadFull(clientPipe, hdr[:])
	if hdr[0] != TLSRecordAppData {
		t.Fatalf("expected appdata record, got %02x", hdr[0])
	}

	recordLen := binary.BigEndian.Uint16(hdr[3:5])
	if int(recordLen) != len(msg) {
		t.Fatalf("expected record len %d, got %d", len(msg), recordLen)
	}

	payload := make([]byte, recordLen)
	io.ReadFull(clientPipe, payload)
	if !bytes.Equal(payload, msg) {
		t.Fatalf("payload mismatch")
	}
}

func TestFakeTLSConn_FullDuplex(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	tls1 := NewFakeTLSConn(c1)
	tls2 := NewFakeTLSConn(c2)

	data1 := []byte("ping from tls1 to tls2")
	data2 := []byte("pong from tls2 to tls1")

	readStarted := make(chan struct{})
	tls1ReadDone := make(chan error, 1)
	tls1WriteDone := make(chan error, 1)
	tls2Done := make(chan error, 1)

	// Goroutine 1: tls1.Read starts first and blocks waiting for data from tls2
	go func() {
		close(readStarted)
		buf := make([]byte, len(data2))
		if _, err := io.ReadFull(tls1, buf); err != nil {
			tls1ReadDone <- err
			return
		}
		if !bytes.Equal(buf, data2) {
			tls1ReadDone <- fmt.Errorf("tls1 read mismatch: got %q, want %q", buf, data2)
			return
		}
		tls1ReadDone <- nil
	}()

	// Wait until tls1.Read is actively blocked on underlying socket
	<-readStarted
	time.Sleep(50 * time.Millisecond)

	// Goroutine 2: tls2 waits to receive data1 from tls1 before sending data2.
	// If tls1.Write blocks on a shared mutex while tls1.Read is blocked, deadlock occurs!
	go func() {
		buf := make([]byte, len(data1))
		if _, err := io.ReadFull(tls2, buf); err != nil {
			tls2Done <- err
			return
		}
		if !bytes.Equal(buf, data1) {
			tls2Done <- fmt.Errorf("tls2 read mismatch: got %q, want %q", buf, data1)
			return
		}
		if _, err := tls2.Write(data2); err != nil {
			tls2Done <- err
			return
		}
		tls2Done <- nil
	}()

	// Goroutine 3: tls1.Write runs concurrently while tls1.Read is already blocked
	go func() {
		if _, err := tls1.Write(data1); err != nil {
			tls1WriteDone <- err
			return
		}
		tls1WriteDone <- nil
	}()

	timeout := time.After(2 * time.Second)
	for i := 0; i < 3; i++ {
		select {
		case err := <-tls1ReadDone:
			if err != nil {
				t.Fatalf("tls1 Read failed: %v", err)
			}
		case err := <-tls1WriteDone:
			if err != nil {
				t.Fatalf("tls1 Write failed: %v", err)
			}
		case err := <-tls2Done:
			if err != nil {
				t.Fatalf("tls2 exchange failed: %v", err)
			}
		case <-timeout:
			t.Fatal("deadlock detected: Read and Write on same FakeTLSConn blocked each other")
		}
	}
}
