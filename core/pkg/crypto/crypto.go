package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"tg-ws-proxy-core/pkg/proto"
)

var (
	ErrInvalidHandshakeLen = errors.New("handshake must be 64 bytes")
	ErrInvalidProtocolTag  = errors.New("unrecognized protocol tag")
)

// HandshakeResult represents parsed MTProto handshake information.
type HandshakeResult struct {
	DCID               int
	IsMedia            bool
	ProtoTag           [4]byte
	ProtoInt           uint32
	ClientDecPrekeyIV  []byte
}

// TryHandshake verifies MTProto handshake and extracts target DC and protocol tag.
func TryHandshake(handshake, secret []byte) (*HandshakeResult, error) {
	if len(handshake) != proto.HandshakeLen {
		return nil, ErrInvalidHandshakeLen
	}

	decPrekeyAndIV := make([]byte, proto.PrekeyLen+proto.IVLen)
	copy(decPrekeyAndIV, handshake[proto.SkipLen:proto.SkipLen+proto.PrekeyLen+proto.IVLen])

	decPrekey := decPrekeyAndIV[:proto.PrekeyLen]
	decIV := decPrekeyAndIV[proto.PrekeyLen:]

	h := sha256.New()
	h.Write(decPrekey)
	h.Write(secret)
	decKey := h.Sum(nil)

	block, err := aes.NewCipher(decKey)
	if err != nil {
		return nil, fmt.Errorf("aes new cipher: %w", err)
	}

	stream := cipher.NewCTR(block, decIV)
	decrypted := make([]byte, proto.HandshakeLen)
	stream.XORKeyStream(decrypted, handshake)

	var protoTag [4]byte
	copy(protoTag[:], decrypted[proto.ProtoTagPos:proto.ProtoTagPos+4])

	var protoInt uint32
	switch protoTag {
	case proto.ProtoTagAbridged:
		protoInt = proto.ProtoAbridgedInt
	case proto.ProtoTagIntermediate:
		protoInt = proto.ProtoIntermediateInt
	case proto.ProtoTagSecure:
		protoInt = proto.ProtoPaddedIntermediateInt
	default:
		return nil, ErrInvalidProtocolTag
	}

	rawDC := binary.LittleEndian.Uint16(decrypted[proto.DCIdxPos : proto.DCIdxPos+2])
	dcIdx := int16(rawDC)

	var dcID int
	var isMedia bool
	if dcIdx < 0 {
		dcID = int(-dcIdx)
		isMedia = true
	} else {
		dcID = int(dcIdx)
		isMedia = false
	}

	return &HandshakeResult{
		DCID:              dcID,
		IsMedia:           isMedia,
		ProtoTag:          protoTag,
		ProtoInt:          protoInt,
		ClientDecPrekeyIV: decPrekeyAndIV,
	}, nil
}

// GenerateRelayInit generates a random 64-byte obfuscated packet to initialize
// connection to Telegram server.
func GenerateRelayInit(protoTag [4]byte, dcIdx int16) ([]byte, error) {
	rnd := make([]byte, proto.HandshakeLen)
	for {
		if _, err := io.ReadFull(rand.Reader, rnd); err != nil {
			return nil, err
		}

		if proto.ReservedFirstBytes[rnd[0]] {
			continue
		}

		var start [4]byte
		copy(start[:], rnd[:4])
		if proto.ReservedStarts[start] {
			continue
		}

		var cont [4]byte
		copy(cont[:], rnd[4:8])
		if cont == proto.ReservedContinue {
			continue
		}
		break
	}

	encKey := rnd[proto.SkipLen : proto.SkipLen+proto.PrekeyLen]
	encIV := rnd[proto.SkipLen+proto.PrekeyLen : proto.SkipLen+proto.PrekeyLen+proto.IVLen]

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, encIV)
	encryptedFull := make([]byte, proto.HandshakeLen)
	stream.XORKeyStream(encryptedFull, rnd)

	var tailPlain [8]byte
	copy(tailPlain[0:4], protoTag[:])
	binary.LittleEndian.PutUint16(tailPlain[4:6], uint16(dcIdx))
	if _, err := io.ReadFull(rand.Reader, tailPlain[6:8]); err != nil {
		return nil, err
	}

	for i := 0; i < 8; i++ {
		rnd[proto.ProtoTagPos+i] = tailPlain[i] ^ encryptedFull[proto.ProtoTagPos+i] ^ rnd[proto.ProtoTagPos+i]
	}
	return rnd, nil
}

// CryptoContext contains 4 streaming ciphers for client and Telegram directions.
type CryptoContext struct {
	CltDec cipher.Stream // Decrypt data from client
	CltEnc cipher.Stream // Encrypt data to client
	TgEnc  cipher.Stream // Encrypt data to Telegram
	TgDec  cipher.Stream // Decrypt data from Telegram
}

func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		out[i] = b[len(b)-1-i]
	}
	return out
}

// NewCryptoContext derives encryption and decryption keys for client and Telegram.
func NewCryptoContext(clientDecPrekeyIV, secret, relayInit []byte) (*CryptoContext, error) {
	cltDecPrekey := clientDecPrekeyIV[:proto.PrekeyLen]
	cltDecIV := clientDecPrekeyIV[proto.PrekeyLen:]

	h1 := sha256.New()
	h1.Write(cltDecPrekey)
	h1.Write(secret)
	cltDecKey := h1.Sum(nil)

	cltDecBlock, err := aes.NewCipher(cltDecKey)
	if err != nil {
		return nil, err
	}
	cltDec := cipher.NewCTR(cltDecBlock, cltDecIV)

	// Fast-forward client decryptor past 64-byte init
	var zero64 [proto.HandshakeLen]byte
	cltDec.XORKeyStream(zero64[:], zero64[:])

	cltEncPrekeyIV := reverseBytes(clientDecPrekeyIV)
	h2 := sha256.New()
	h2.Write(cltEncPrekeyIV[:proto.PrekeyLen])
	h2.Write(secret)
	cltEncKey := h2.Sum(nil)

	cltEncBlock, err := aes.NewCipher(cltEncKey)
	if err != nil {
		return nil, err
	}
	cltEnc := cipher.NewCTR(cltEncBlock, cltEncPrekeyIV[proto.PrekeyLen:])

	// Relay side (standard obfuscation, raw key without secret)
	relayEncKey := relayInit[proto.SkipLen : proto.SkipLen+proto.PrekeyLen]
	relayEncIV := relayInit[proto.SkipLen+proto.PrekeyLen : proto.SkipLen+proto.PrekeyLen+proto.IVLen]

	tgEncBlock, err := aes.NewCipher(relayEncKey)
	if err != nil {
		return nil, err
	}
	tgEnc := cipher.NewCTR(tgEncBlock, relayEncIV)

	// Fast-forward Telegram encryptor past 64-byte init
	var zero64TG [proto.HandshakeLen]byte
	tgEnc.XORKeyStream(zero64TG[:], zero64TG[:])

	relayDecPrekeyIV := reverseBytes(relayInit[proto.SkipLen : proto.SkipLen+proto.PrekeyLen+proto.IVLen])
	relayDecKey := relayDecPrekeyIV[:proto.KeyLen]
	relayDecIV := relayDecPrekeyIV[proto.KeyLen:]

	tgDecBlock, err := aes.NewCipher(relayDecKey)
	if err != nil {
		return nil, err
	}
	tgDec := cipher.NewCTR(tgDecBlock, relayDecIV)

	return &CryptoContext{
		CltDec: cltDec,
		CltEnc: cltEnc,
		TgEnc:  tgEnc,
		TgDec:  tgDec,
	}, nil
}
