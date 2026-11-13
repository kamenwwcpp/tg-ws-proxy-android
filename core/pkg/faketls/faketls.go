package faketls

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"time"
)

const (
	TLSRecordHandshake = 0x16
	TLSRecordCCS       = 0x14
	TLSRecordAppData   = 0x17

	ClientRandomOffset = 11
	ClientRandomLen    = 32
	SessionIDOffset    = 44
	SessionIDLen       = 32

	TimestampTolerance = 120 // seconds
	TLSAppDataMax      = 16384
)

var (
	ErrInvalidTLSHeader   = errors.New("invalid TLS header")
	ErrFakeTLSVerifyFail  = errors.New("fake TLS verification failed")
	ErrTimestampExpired   = errors.New("fake TLS timestamp expired or skewed")
	ErrIncompleteRecord   = errors.New("incomplete TLS record")

	ccsFrame = []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}

	serverHelloTemplate = []byte{
		0x16, 0x03, 0x03, 0x00, 0x7a, // Record Header: Handshake, TLS 1.2, len 122
		0x02, 0x00, 0x00, 0x76, // ServerHello, len 118
		0x03, 0x03, // TLS 1.2
		// 32 bytes random placeholder (offset 11..43)
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0x20, // Session ID len 32 (offset 43)
		// 32 bytes session ID placeholder (offset 44..76)
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0x13, 0x01, // Cipher suite TLS_AES_128_GCM_SHA256
		0x00,       // Compression none
		0x00, 0x2e, // Extensions len 46
		// Key share extension: type 0x0033, len 0x0024, group x25519 (0x001d), key len 0x0020
		0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20,
		// 32 bytes pubkey placeholder (offset 89..121)
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// Supported versions extension: TLS 1.3
		0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
	}

	shSessIDOffset = 44
	shPubKeyOffset = 89
	shRandomOffset = 11
)

// ClientHelloInfo holds information parsed from a valid Fake TLS ClientHello.
type ClientHelloInfo struct {
	ClientRandom []byte
	SessionID    []byte
	Timestamp    int64
}

// VerifyClientHello validates a ClientHello against the MTProto secret.
func VerifyClientHello(data, secret []byte) (*ClientHelloInfo, error) {
	n := len(data)
	if n < 43 || data[0] != TLSRecordHandshake || data[5] != 0x01 {
		return nil, ErrInvalidTLSHeader
	}

	clientRandom := make([]byte, ClientRandomLen)
	copy(clientRandom, data[ClientRandomOffset:ClientRandomOffset+ClientRandomLen])

	zeroed := make([]byte, len(data))
	copy(zeroed, data)
	for i := 0; i < ClientRandomLen; i++ {
		zeroed[ClientRandomOffset+i] = 0
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(zeroed)
	expected := mac.Sum(nil)

	if !hmac.Equal(expected[:28], clientRandom[:28]) {
		return nil, ErrFakeTLSVerifyFail
	}

	tsXOR := make([]byte, 4)
	for i := 0; i < 4; i++ {
		tsXOR[i] = clientRandom[28+i] ^ expected[28+i]
	}
	timestamp := int64(binary.LittleEndian.Uint32(tsXOR))

	now := time.Now().Unix()
	diff := now - timestamp
	if diff < 0 {
		diff = -diff
	}
	if diff > TimestampTolerance {
		return nil, ErrTimestampExpired
	}

	sessionID := make([]byte, SessionIDLen)
	if n >= SessionIDOffset+SessionIDLen && data[43] == 0x20 {
		copy(sessionID, data[SessionIDOffset:SessionIDOffset+SessionIDLen])
	}

	return &ClientHelloInfo{
		ClientRandom: clientRandom,
		SessionID:    sessionID,
		Timestamp:    timestamp,
	}, nil
}

// BuildServerHello constructs the fake TLS ServerHello response matching the client.
func BuildServerHello(secret, clientRandom, sessionID []byte) ([]byte, error) {
	sh := make([]byte, len(serverHelloTemplate))
	copy(sh, serverHelloTemplate)
	copy(sh[shSessIDOffset:shSessIDOffset+32], sessionID)

	if _, err := io.ReadFull(rand.Reader, sh[shPubKeyOffset:shPubKeyOffset+32]); err != nil {
		return nil, err
	}

	// Random encrypted size between 1900 and 2100
	nBig, err := rand.Int(rand.Reader, big.NewInt(201))
	if err != nil {
		return nil, err
	}
	encryptedSize := 1900 + int(nBig.Int64())

	encryptedData := make([]byte, encryptedSize)
	if _, err := io.ReadFull(rand.Reader, encryptedData); err != nil {
		return nil, err
	}

	appRecord := make([]byte, 5+encryptedSize)
	appRecord[0] = TLSRecordAppData
	appRecord[1] = 0x03
	appRecord[2] = 0x03
	binary.BigEndian.PutUint16(appRecord[3:5], uint16(encryptedSize))
	copy(appRecord[5:], encryptedData)

	response := make([]byte, 0, len(sh)+len(ccsFrame)+len(appRecord))
	response = append(response, sh...)
	response = append(response, ccsFrame...)
	response = append(response, appRecord...)

	mac := hmac.New(sha256.New, secret)
	mac.Write(clientRandom)
	mac.Write(response)
	serverRandom := mac.Sum(nil)

	copy(response[shRandomOffset:shRandomOffset+32], serverRandom)
	return response, nil
}

// FakeTLSConn wraps a net.Conn with TLS Application Data (0x17) record framing.
type FakeTLSConn struct {
	net.Conn
	readBuf []byte
	readMu  sync.Mutex
	writeMu sync.Mutex
}

// NewFakeTLSConn creates a FakeTLSConn wrapping an established net.Conn.
func NewFakeTLSConn(conn net.Conn) *FakeTLSConn {
	return &FakeTLSConn{
		Conn:    conn,
		readBuf: make([]byte, 0, 4096),
	}
}

// Read reads and unboxes TLS Application Data frames.
func (c *FakeTLSConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for len(c.readBuf) == 0 {
		var hdr [5]byte
		if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
			return 0, err
		}

		recordLen := binary.BigEndian.Uint16(hdr[3:5])
		payload := make([]byte, recordLen)
		if _, err := io.ReadFull(c.Conn, payload); err != nil {
			return 0, err
		}

		if hdr[0] == TLSRecordAppData {
			c.readBuf = append(c.readBuf, payload...)
		}
		// Ignore non-appdata records if any (e.g. CCS or renegotiation notices)
	}

	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	if len(c.readBuf) == 0 {
		c.readBuf = c.readBuf[:0]
	}
	return n, nil
}

// Write wraps outgoing data in TLS Application Data records (max 16KB per chunk).
func (c *FakeTLSConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	total := len(p)
	offset := 0

	for offset < total {
		chunkSize := total - offset
		if chunkSize > TLSAppDataMax {
			chunkSize = TLSAppDataMax
		}

		record := make([]byte, 5+chunkSize)
		record[0] = TLSRecordAppData
		record[1] = 0x03
		record[2] = 0x03
		binary.BigEndian.PutUint16(record[3:5], uint16(chunkSize))
		copy(record[5:], p[offset:offset+chunkSize])

		if _, err := c.Conn.Write(record); err != nil {
			return offset, err
		}
		offset += chunkSize
	}

	return total, nil
}
