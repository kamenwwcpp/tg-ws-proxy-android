package proxy

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"tg-ws-proxy-core/pkg/config"
	"tg-ws-proxy-core/pkg/faketls"
)

func TestServer_FakeTLSEndToEnd(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.IsFakeTLS = true
	cfg.FakeTLSDomain = "google.com"

	secret := make([]byte, 16)
	rand.Read(secret)
	cfg.SecretBytes = secret

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := NewServer(cfg)

	// Find assigned port by listening directly
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg.ListenAddr = addr
	go func() {
		_ = srv.Start(ctx)
	}()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("failed to dial server: %v", err)
	}
	defer conn.Close()

	// 1. Build ClientHello
	ch := make([]byte, 512)
	rand.Read(ch)
	ch[0] = faketls.TLSRecordHandshake
	ch[1] = 0x03
	ch[2] = 0x01
	binary.BigEndian.PutUint16(ch[3:5], uint16(len(ch)-5))
	ch[5] = 0x01
	ch[6] = 0x00
	binary.BigEndian.PutUint16(ch[7:9], uint16(len(ch)-9))
	ch[9] = 0x03
	ch[10] = 0x03
	ch[43] = 0x20

	for i := 0; i < 32; i++ {
		ch[faketls.ClientRandomOffset+i] = 0
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(ch)
	expected := mac.Sum(nil)
	copy(ch[faketls.ClientRandomOffset:faketls.ClientRandomOffset+28], expected[:28])

	var tsBytes [4]byte
	binary.LittleEndian.PutUint32(tsBytes[:], uint32(time.Now().Unix()))
	for i := 0; i < 4; i++ {
		ch[faketls.ClientRandomOffset+28+i] = tsBytes[i] ^ expected[28+i]
	}

	// Send ClientHello
	if _, err := conn.Write(ch); err != nil {
		t.Fatalf("write client hello failed: %v", err)
	}

	// Read ServerHello
	var shHdr [5]byte
	if _, err := io.ReadFull(conn, shHdr[:]); err != nil {
		t.Fatalf("read server hello hdr failed: %v", err)
	}
	if shHdr[0] != faketls.TLSRecordHandshake {
		t.Fatalf("expected server hello handshake, got %02x", shHdr[0])
	}
}

func TestServer_DialFastUpstreamFailsGracefully(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.FallbackCF = false
	srv := NewServer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	wsConn, domain, err := srv.dialFastUpstream(ctx, 999, false)
	if wsConn != nil {
		wsConn.Close()
		t.Fatal("expected no connection")
	}
	if err == nil {
		t.Fatal("expected error for non-existent routes")
	}
	_ = domain
}

func TestServeClosesClientsOnNetworkLossAndStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := NewServer(config.DefaultConfig())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, ln) }()
	dial := func() net.Conn {
		t.Helper()
		conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		return conn
	}
	expectClosed := func(conn net.Conn) {
		t.Helper()
		var b [1]byte
		_, err := conn.Read(b[:])
		if err == nil || os.IsTimeout(err) {
			t.Fatalf("connection did not close promptly: %v", err)
		}
	}
	client := dial()
	server.SetNetwork(false, 0, false)
	expectClosed(client)
	expectClosed(dial())
	server.SetNetwork(true, 2, false)
	client = dial()
	cancel()
	expectClosed(client)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
}
