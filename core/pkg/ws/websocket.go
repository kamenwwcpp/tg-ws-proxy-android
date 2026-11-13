package ws

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	OpCont   byte = 0x0
	OpText   byte = 0x1
	OpBinary byte = 0x2
	OpClose  byte = 0x8
	OpPing   byte = 0x9
	OpPong   byte = 0xA

	MaxMessageLen = 16 * 1024 * 1024 // 16 MB
)

var (
	ErrWebSocketClosed = errors.New("websocket connection closed")
	ErrMessageTooLarge = errors.New("websocket message exceeded max limit")
	ErrInvalidOpcode   = errors.New("unsupported websocket opcode")
	ErrHandshakeFailed = errors.New("websocket handshake failed")
)

// RawWebSocket provides RFC 6455 framing over TLS/TCP connection.
type RawWebSocket struct {
	conn    net.Conn
	reader  *bufio.Reader
	writer  *bufio.Writer
	muWrite sync.Mutex
	closed  bool
	muClose sync.Mutex
	fragBuf []byte
}

// DialOptions holds connection parameters.
type DialOptions struct {
	Context    context.Context
	Host       string
	Port       int
	Domain     string
	SNI        string
	Path       string
	Secure     bool
	Timeout    time.Duration
	BufferSize int
}

type dnsCacheEntry struct {
	ips       []net.IP
	expiresAt time.Time
}

const (
	maxDNSCacheEntries = 256
	dnsCacheTTL        = 10 * time.Minute
)

var (
	dnsCacheMu sync.RWMutex
	dnsCache   = make(map[string]dnsCacheEntry)
	dnsServers = []string{
		"77.88.8.8:53", // Yandex DNS (uncensored, ultra-fast in RU/CIS)
		"1.1.1.1:53",   // Cloudflare DNS
		"8.8.8.8:53",   // Google DNS
	}
)

func storeDNSCache(host string, ips []net.IP) {
	now := time.Now()
	dnsCacheMu.Lock()
	defer dnsCacheMu.Unlock()

	if len(dnsCache) >= maxDNSCacheEntries {
		for h, e := range dnsCache {
			if now.After(e.expiresAt) {
				delete(dnsCache, h)
			}
		}
		if len(dnsCache) >= maxDNSCacheEntries {
			for h := range dnsCache {
				delete(dnsCache, h)
				if len(dnsCache) < maxDNSCacheEntries/2 {
					break
				}
			}
		}
	}

	dnsCache[host] = dnsCacheEntry{
		ips:       ips,
		expiresAt: now.Add(dnsCacheTTL),
	}
}

func resolveHostFast(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}

	now := time.Now()
	dnsCacheMu.RLock()
	entry, found := dnsCache[host]
	dnsCacheMu.RUnlock()
	if found && now.Before(entry.expiresAt) && len(entry.ips) > 0 {
		return entry.ips, nil
	}

	var lastErr error
	for _, srv := range dnsServers {
		srvAddr := srv
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "udp", srvAddr)
			},
		}

		subCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		ips, err := resolver.LookupIP(subCtx, "ip4", host)
		cancel()

		if err == nil && len(ips) > 0 {
			storeDNSCache(host, ips)
			return ips, nil
		}
		lastErr = err
	}

	systemResolver := net.DefaultResolver
	ips, err := systemResolver.LookupIP(ctx, "ip4", host)
	if err == nil && len(ips) > 0 {
		storeDNSCache(host, ips)
		return ips, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("dns for %s failed: %w", host, lastErr)
	}
	return nil, fmt.Errorf("no IP found for %s", host)
}

// Connect dials the remote host and completes the WebSocket HTTP upgrade handshake.
func Connect(opts DialOptions) (*RawWebSocket, error) {
	if opts.Path == "" {
		opts.Path = "/apiws"
	}
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.BufferSize == 0 {
		opts.BufferSize = 65536
	}

	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}
	var cancel context.CancelFunc
	if opts.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	port := opts.Port
	if port == 0 {
		if opts.Secure {
			port = 443
		} else {
			port = 80
		}
	}

	ips, err := resolveHostFast(ctx, opts.Host)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{}

	sni := opts.SNI
	if sni == "" {
		sni = opts.Domain
	}

	var rawConn net.Conn
	var dialErr error
	for _, ip := range ips {
		targetAddr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
		rawConn, dialErr = dialer.DialContext(ctx, "tcp", targetAddr)
		if dialErr == nil {
			break
		}
	}
	if dialErr != nil || rawConn == nil {
		return nil, fmt.Errorf("dial failed: %w", dialErr)
	}

	// Optimize socket options immediately on raw TCP socket
	if tc, ok := rawConn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetReadBuffer(opts.BufferSize)
		_ = tc.SetWriteBuffer(opts.BufferSize)
	}

	if opts.Secure {
		tlsConfig := &tls.Config{
			ServerName:       sni,
			MinVersion:       tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		}
		tlsConn := tls.Client(rawConn, tlsConfig)
		err := tlsConn.HandshakeContext(ctx)
		if err != nil {
			_ = rawConn.Close()
			return nil, fmt.Errorf("tls handshake failed: %w", err)
		}
		rawConn = tlsConn
	}

	wsKeyBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, wsKeyBytes); err != nil {
		rawConn.Close()
		return nil, err
	}
	wsKey := base64.StdEncoding.EncodeToString(wsKeyBytes)

	req := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"Sec-WebSocket-Protocol: binary\r\n\r\n",
		opts.Path, opts.Domain, wsKey,
	)

	tcpConn := rawConn
	stopHandshake := context.AfterFunc(ctx, func() { _ = tcpConn.SetDeadline(time.Now()) })
	defer stopHandshake()
	if deadline, ok := ctx.Deadline(); ok {
		_ = rawConn.SetDeadline(deadline)
	}
	if _, err := rawConn.Write([]byte(req)); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("write handshake failed: %w", err)
	}

	br := bufio.NewReaderSize(rawConn, opts.BufferSize)
	bw := bufio.NewWriterSize(rawConn, opts.BufferSize)

	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("read handshake response failed: %w", err)
	}
	if !stopHandshake() || ctx.Err() != nil {
		rawConn.Close()
		return nil, ctx.Err()
	}
	_ = rawConn.SetDeadline(time.Time{})

	if resp.StatusCode != http.StatusSwitchingProtocols {
		rawConn.Close()
		return nil, fmt.Errorf("%w: status %d %s", ErrHandshakeFailed, resp.StatusCode, resp.Status)
	}

	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		rawConn.Close()
		return nil, fmt.Errorf("%w: missing Upgrade: websocket", ErrHandshakeFailed)
	}

	return &RawWebSocket{
		conn:    rawConn,
		reader:  br,
		writer:  bw,
		fragBuf: make([]byte, 0, 8192),
	}, nil
}

// Send transmits data as a masked binary frame (RFC 6455).
func (ws *RawWebSocket) Send(data []byte) error {
	ws.muClose.Lock()
	if ws.closed {
		ws.muClose.Unlock()
		return ErrWebSocketClosed
	}
	ws.muClose.Unlock()

	ws.muWrite.Lock()
	defer ws.muWrite.Unlock()

	frame := buildFrame(OpBinary, data, true)
	if _, err := ws.writer.Write(frame); err != nil {
		return err
	}
	return ws.writer.Flush()
}

// SendBatch transmits multiple binary frames in a single flush.
func (ws *RawWebSocket) SendBatch(parts [][]byte) error {
	ws.muClose.Lock()
	if ws.closed {
		ws.muClose.Unlock()
		return ErrWebSocketClosed
	}
	ws.muClose.Unlock()

	ws.muWrite.Lock()
	defer ws.muWrite.Unlock()

	for _, part := range parts {
		frame := buildFrame(OpBinary, part, true)
		if _, err := ws.writer.Write(frame); err != nil {
			return err
		}
	}
	return ws.writer.Flush()
}

// Ping transmits an RFC 6455 Ping frame (masked) to keep upstream connection alive.
func (ws *RawWebSocket) Ping() error {
	ws.muClose.Lock()
	if ws.closed {
		ws.muClose.Unlock()
		return ErrWebSocketClosed
	}
	ws.muClose.Unlock()

	ws.muWrite.Lock()
	defer ws.muWrite.Unlock()

	frame := buildFrame(OpPing, nil, true)
	if _, err := ws.writer.Write(frame); err != nil {
		return err
	}
	return ws.writer.Flush()
}

// Recv reads the next complete message from the WebSocket connection.
func (ws *RawWebSocket) Recv() ([]byte, error) {
	for {
		ws.muClose.Lock()
		if ws.closed {
			ws.muClose.Unlock()
			return nil, ErrWebSocketClosed
		}
		ws.muClose.Unlock()

		opcode, payload, fin, err := ws.readFrame()
		if err != nil {
			return nil, err
		}

		switch opcode {
		case OpClose:
			ws.muClose.Lock()
			ws.closed = true
			ws.muClose.Unlock()

			_ = ws.conn.SetWriteDeadline(time.Now().Add(time.Second))
			defer ws.conn.Close()
			ws.muWrite.Lock()
			reply := buildFrame(OpClose, payload, true)
			_, _ = ws.writer.Write(reply)
			_ = ws.writer.Flush()
			ws.muWrite.Unlock()
			return nil, ErrWebSocketClosed

		case OpPing:
			ws.muWrite.Lock()
			pong := buildFrame(OpPong, payload, true)
			_, _ = ws.writer.Write(pong)
			_ = ws.writer.Flush()
			ws.muWrite.Unlock()
			continue

		case OpPong:
			continue

		case OpCont, OpBinary, OpText:
			if fin && len(ws.fragBuf) == 0 {
				return payload, nil
			}

			ws.fragBuf = append(ws.fragBuf, payload...)
			if len(ws.fragBuf) > MaxMessageLen {
				return nil, ErrMessageTooLarge
			}

			if fin {
				msg := make([]byte, len(ws.fragBuf))
				copy(msg, ws.fragBuf)
				ws.fragBuf = ws.fragBuf[:0]
				return msg, nil
			}
			continue

		default:
			return nil, ErrInvalidOpcode
		}
	}
}

func (ws *RawWebSocket) Close() error {
	ws.muClose.Lock()
	alreadyClosed := ws.closed
	ws.closed = true
	ws.muClose.Unlock()
	if !alreadyClosed {
		_ = ws.conn.SetWriteDeadline(time.Now().Add(250 * time.Millisecond))
		ws.muWrite.Lock()
		_, _ = ws.writer.Write(buildFrame(OpClose, nil, true))
		_ = ws.writer.Flush()
		ws.muWrite.Unlock()
	}
	return ws.conn.Close()
}

func buildFrame(opcode byte, payload []byte, mask bool) []byte {
	n := len(payload)
	headerLen := 2
	if mask {
		headerLen += 4
	}

	var lenBytes int
	if n <= 125 {
		lenBytes = 0
	} else if n <= 65535 {
		lenBytes = 2
	} else {
		lenBytes = 8
	}
	headerLen += lenBytes

	frame := make([]byte, headerLen+n)
	frame[0] = 0x80 | (opcode & 0x0F) // FIN = 1

	maskBit := byte(0)
	if mask {
		maskBit = 0x80
	}

	offset := 2
	if n <= 125 {
		frame[1] = maskBit | byte(n)
	} else if n <= 65535 {
		frame[1] = maskBit | 126
		binary.BigEndian.PutUint16(frame[2:4], uint16(n))
		offset = 4
	} else {
		frame[1] = maskBit | 127
		binary.BigEndian.PutUint64(frame[2:10], uint64(n))
		offset = 10
	}

	if mask {
		var maskKey [4]byte
		_, _ = io.ReadFull(rand.Reader, maskKey[:])
		copy(frame[offset:offset+4], maskKey[:])
		offset += 4

		for i := 0; i < n; i++ {
			frame[offset+i] = payload[i] ^ maskKey[i%4]
		}
	} else {
		copy(frame[offset:], payload)
	}

	return frame
}

func (ws *RawWebSocket) readFrame() (opcode byte, payload []byte, fin bool, err error) {
	b0, err := ws.reader.ReadByte()
	if err != nil {
		return 0, nil, false, err
	}

	fin = (b0 & 0x80) != 0
	opcode = b0 & 0x0F

	b1, err := ws.reader.ReadByte()
	if err != nil {
		return 0, nil, false, err
	}

	hasMask := (b1 & 0x80) != 0
	payloadLen := uint64(b1 & 0x7F)

	if payloadLen == 126 {
		var l16 [2]byte
		if _, err := io.ReadFull(ws.reader, l16[:]); err != nil {
			return 0, nil, false, err
		}
		payloadLen = uint64(binary.BigEndian.Uint16(l16[:]))
	} else if payloadLen == 127 {
		var l64 [8]byte
		if _, err := io.ReadFull(ws.reader, l64[:]); err != nil {
			return 0, nil, false, err
		}
		payloadLen = binary.BigEndian.Uint64(l64[:])
	}

	if payloadLen > MaxMessageLen {
		return 0, nil, false, ErrMessageTooLarge
	}

	var maskKey [4]byte
	if hasMask {
		if _, err := io.ReadFull(ws.reader, maskKey[:]); err != nil {
			return 0, nil, false, err
		}
	}

	data := make([]byte, payloadLen)
	if _, err := io.ReadFull(ws.reader, data); err != nil {
		return 0, nil, false, err
	}

	if hasMask {
		for i := 0; i < int(payloadLen); i++ {
			data[i] ^= maskKey[i%4]
		}
	}

	return opcode, data, fin, nil
}
