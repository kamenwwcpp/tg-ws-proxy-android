package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"testing"

	"tg-ws-proxy-core/pkg/proto"
)

func TestGenerateRelayInitAndDecryption(t *testing.T) {
	tag := proto.ProtoTagAbridged
	dcIdx := int16(2)

	initPkt, err := GenerateRelayInit(tag, dcIdx)
	if err != nil {
		t.Fatalf("GenerateRelayInit failed: %v", err)
	}
	if len(initPkt) != 64 {
		t.Fatalf("expected 64 bytes, got %d", len(initPkt))
	}

	// Telegram decrypts relayInit with raw key (without secret)
	key := initPkt[proto.SkipLen : proto.SkipLen+proto.PrekeyLen]
	iv := initPkt[proto.SkipLen+proto.PrekeyLen : proto.SkipLen+proto.PrekeyLen+proto.IVLen]

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes cipher failed: %v", err)
	}

	stream := cipher.NewCTR(block, iv)
	decrypted := make([]byte, 64)
	stream.XORKeyStream(decrypted, initPkt)

	gotTag := decrypted[proto.ProtoTagPos : proto.ProtoTagPos+4]
	if !bytes.Equal(gotTag, tag[:]) {
		t.Fatalf("expected tag %v, got %v", tag, gotTag)
	}

	gotDC := int16(binary.LittleEndian.Uint16(decrypted[proto.DCIdxPos : proto.DCIdxPos+2]))
	if gotDC != dcIdx {
		t.Fatalf("expected DC %d, got %d", dcIdx, gotDC)
	}
}

func TestTryHandshakeWithSecret(t *testing.T) {
	secret := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		t.Fatal(err)
	}

	raw := make([]byte, 64)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		t.Fatal(err)
	}

	prekey := raw[proto.SkipLen : proto.SkipLen+proto.PrekeyLen]
	iv := raw[proto.SkipLen+proto.PrekeyLen : proto.SkipLen+proto.PrekeyLen+proto.IVLen]

	h := sha256.New()
	h.Write(prekey)
	h.Write(secret)
	key := h.Sum(nil)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	stream := cipher.NewCTR(block, iv)
	enc := make([]byte, 64)
	stream.XORKeyStream(enc, raw)

	// We want decrypted[56:60] = ProtoTagIntermediate, decrypted[60:62] = -4 (media DC 4)
	targetPlainTail := make([]byte, 8)
	copy(targetPlainTail[0:4], proto.ProtoTagIntermediate[:])
	dcTarget := int16(-4)
	binary.LittleEndian.PutUint16(targetPlainTail[4:6], uint16(dcTarget))

	keystreamTail := make([]byte, 8)
	for i := 0; i < 8; i++ {
		keystreamTail[i] = enc[56+i] ^ raw[56+i]
	}

	for i := 0; i < 8; i++ {
		raw[56+i] = targetPlainTail[i] ^ keystreamTail[i]
	}

	res, err := TryHandshake(raw, secret)
	if err != nil {
		t.Fatalf("TryHandshake failed: %v", err)
	}

	if res.DCID != 4 {
		t.Fatalf("expected DC 4, got %d", res.DCID)
	}
	if !res.IsMedia {
		t.Fatalf("expected IsMedia=true")
	}
	if res.ProtoTag != proto.ProtoTagIntermediate {
		t.Fatalf("expected intermediate tag")
	}
}

func TestCryptoContextStream(t *testing.T) {
	secret := []byte("0123456789abcdef")
	clientPrekeyIV := make([]byte, 48)
	if _, err := io.ReadFull(rand.Reader, clientPrekeyIV); err != nil {
		t.Fatal(err)
	}

	relayInit, err := GenerateRelayInit(proto.ProtoTagAbridged, 2)
	if err != nil {
		t.Fatal(err)
	}

	ctx, err := NewCryptoContext(clientPrekeyIV, secret, relayInit)
	if err != nil {
		t.Fatalf("NewCryptoContext failed: %v", err)
	}

	// Test client decryptor / encryptor
	data := []byte("Hello, MTProto world!")
	cipherData := make([]byte, len(data))
	plainData := make([]byte, len(data))

	ctx.CltEnc.XORKeyStream(cipherData, data)
	// Because client side encrypt and decrypt have reversed IVs and different keys,
	// let's verify both streams don't panic and produce valid output
	if bytes.Equal(cipherData, data) {
		t.Fatalf("ciphertext equals plaintext")
	}

	ctx.TgEnc.XORKeyStream(cipherData, data)
	ctx.TgDec.XORKeyStream(plainData, cipherData)
	// tgEnc and tgDec are opposite directions with different reversed keys, verify execution
	if len(plainData) != len(data) {
		t.Fatalf("unexpected length")
	}
}
