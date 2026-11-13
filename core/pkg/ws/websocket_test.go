package ws

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestWebSocketHandshakeAndFrames(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port

	// Simulated server
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read HTTP handshake
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}

		reqStr := string(buf[:n])
		if !bytes.Contains(buf[:n], []byte("Upgrade: websocket")) {
			return
		}

		// Respond with 101 Switching Protocols
		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
		_, _ = conn.Write([]byte(resp))

		_ = reqStr

		// Read client frame (binary masked)
		// Header 2 bytes
		var h [2]byte
		conn.Read(h[:])
		payloadLen := int(h[1] & 0x7F)
		var mask [4]byte
		conn.Read(mask[:])
		payload := make([]byte, payloadLen)
		conn.Read(payload)

		// Unmask
		for i := 0; i < payloadLen; i++ {
			payload[i] ^= mask[i%4]
		}

		// Echo back unmasked binary frame
		reply := make([]byte, 2+payloadLen)
		reply[0] = 0x82 // FIN + Binary
		reply[1] = byte(payloadLen)
		copy(reply[2:], payload)
		conn.Write(reply)
	}()

	client, err := Connect(DialOptions{
		Host:    "127.0.0.1",
		Port:    port,
		Domain:  fmt.Sprintf("127.0.0.1:%d", port),
		Secure:  false,
		Timeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	testData := []byte("Hello, Telegram WS gateway!")
	if err := client.Send(testData); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	reply, err := client.Recv()
	if err != nil {
		t.Fatalf("Recv failed: %v", err)
	}

	if !bytes.Equal(reply, testData) {
		t.Fatalf("echo mismatch: got %s, want %s", string(reply), string(testData))
	}
}

func TestReadFrameRejectsOversizedLengths(t *testing.T) {
	for _, length := range []uint64{MaxMessageLen + 1, 1 << 63, ^uint64(0)} {
		t.Run(strconv.FormatUint(length, 10), func(t *testing.T) {
			frame := make([]byte, 10)
			frame[0], frame[1] = 0x82, 127
			binary.BigEndian.PutUint64(frame[2:], length)
			client := &RawWebSocket{reader: bufio.NewReader(bytes.NewReader(frame))}
			if _, _, _, err := client.readFrame(); !errors.Is(err, ErrMessageTooLarge) {
				t.Fatalf("got %v, want %v", err, ErrMessageTooLarge)
			}
		})
	}
}

func TestConnectRejectsUntrustedTLS(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	host, portString, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		t.Fatal(err)
	}
	client, err := Connect(DialOptions{Host: host, Port: port, Domain: "example.com", Secure: true, Timeout: time.Second})
	if err == nil {
		client.Close()
		t.Fatal("accepted an untrusted certificate")
	}
	if !strings.Contains(err.Error(), "tls handshake failed") {
		t.Fatalf("expected TLS verification failure, got %v", err)
	}
}

func TestTLSRejectsMissingServerName(t *testing.T) {
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	client := tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS12})
	if err := client.Handshake(); err == nil || !strings.Contains(err.Error(), "either ServerName or InsecureSkipVerify must be specified") {
		t.Fatalf("unexpected handshake result: %v", err)
	}
}

func TestCloseSendsCloseFrame(t *testing.T) {
	conn, peer := net.Pipe()
	defer peer.Close()
	client := &RawWebSocket{conn: conn, writer: bufio.NewWriter(conn)}
	defer client.Close()
	result := make(chan error, 1)
	go func() { result <- client.Close() }()
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var frame [6]byte
	if _, err := io.ReadFull(peer, frame[:]); err != nil {
		t.Fatal(err)
	}
	if frame[0] != 0x88 || frame[1] != 0x80 {
		t.Fatalf("expected masked Close frame, got %x", frame)
	}
	if _, err := peer.Read(frame[:]); err != io.EOF {
		t.Fatalf("socket remained open: %v", err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestCloseInterruptsBlockedSend(t *testing.T) {
	conn, peer := net.Pipe()
	defer peer.Close()
	client := &RawWebSocket{conn: conn, writer: bufio.NewWriter(conn)}
	defer client.Close()
	sent := make(chan error, 1)
	go func() { sent <- client.Send([]byte("test")) }()
	var header [1]byte
	if _, err := io.ReadFull(peer, header[:]); err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() { client.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close blocked on writer")
	}
	select {
	case err := <-sent:
		if err == nil {
			t.Fatal("blocked send succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("send remained blocked")
	}
}

func TestReceivedCloseClosesSocket(t *testing.T) {
	conn, peer := net.Pipe()
	defer peer.Close()
	client := &RawWebSocket{conn: conn, reader: bufio.NewReader(conn), writer: bufio.NewWriter(conn)}
	defer client.Close()
	peerResult := make(chan error, 1)
	go func() {
		if _, err := peer.Write([]byte{0x88, 0}); err != nil {
			peerResult <- err
			return
		}
		_, err := io.Copy(io.Discard, peer)
		peerResult <- err
	}()
	if _, err := client.Recv(); !errors.Is(err, ErrWebSocketClosed) {
		t.Fatalf("got %v, want %v", err, ErrWebSocketClosed)
	}
	select {
	case err := <-peerResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("socket remained open")
	}
}

func TestBuildFrame_RandomSizes(t *testing.T) {
	sizes := []int{10, 125, 126, 1024, 65535, 70000}
	for _, sz := range sizes {
		data := make([]byte, sz)
		rand.Read(data)
		frame := buildFrame(OpBinary, data, true)
		if len(frame) < sz+2 {
			t.Fatalf("frame too short for size %d", sz)
		}
	}
}

func TestDNSCache_Bounded(t *testing.T) {
	dummyIP := []net.IP{net.ParseIP("1.2.3.4")}
	for i := 0; i < maxDNSCacheEntries+50; i++ {
		storeDNSCache(fmt.Sprintf("host-%d.test", i), dummyIP)
	}

	dnsCacheMu.RLock()
	count := len(dnsCache)
	dnsCacheMu.RUnlock()

	if count > maxDNSCacheEntries {
		t.Fatalf("dnsCache exceeded max capacity: %d > %d", count, maxDNSCacheEntries)
	}
}
