package config

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.ListenAddr != "127.0.0.1:1443" {
		t.Fatalf("unexpected listen addr: %s", cfg.ListenAddr)
	}
	if !cfg.IsFakeTLS {
		t.Fatal("expected FakeTLS by default")
	}
	if len(cfg.SecretBytes) != 16 {
		t.Fatalf("expected 16-byte secret, got %d", len(cfg.SecretBytes))
	}
}

func TestConfig_ParseSecret_PlainHex(t *testing.T) {
	cfg := DefaultConfig()
	raw := "0123456789abcdef0123456789abcdef"
	if err := cfg.ParseSecret(raw); err != nil {
		t.Fatalf("failed to parse valid plain hex: %v", err)
	}
	if hex.EncodeToString(cfg.SecretBytes) != raw {
		t.Fatalf("secret bytes mismatch: %x", cfg.SecretBytes)
	}
}

func TestConfig_ParseSecret_FakeTLS(t *testing.T) {
	cfg := DefaultConfig()
	rawSecret := "0123456789abcdef0123456789abcdef"
	domain := "example.com"
	domainHex := hex.EncodeToString([]byte(domain))
	fullSecret := "ee" + rawSecret + domainHex

	if err := cfg.ParseSecret(fullSecret); err != nil {
		t.Fatalf("failed to parse FakeTLS secret: %v", err)
	}
	if !cfg.IsFakeTLS {
		t.Fatal("expected IsFakeTLS=true")
	}
	if cfg.FakeTLSDomain != domain {
		t.Fatalf("expected domain %s, got %s", domain, cfg.FakeTLSDomain)
	}
	if hex.EncodeToString(cfg.SecretBytes) != rawSecret {
		t.Fatalf("secret mismatch: %x", cfg.SecretBytes)
	}
}

func TestConfig_ParseSecret_PaddedDD(t *testing.T) {
	cfg := DefaultConfig()
	rawSecret := "0123456789abcdef0123456789abcdef"
	fullSecret := "dd" + rawSecret

	if err := cfg.ParseSecret(fullSecret); err != nil {
		t.Fatalf("failed to parse dd secret: %v", err)
	}
	if cfg.IsFakeTLS {
		t.Fatal("expected IsFakeTLS=false for dd secret")
	}
	if hex.EncodeToString(cfg.SecretBytes) != rawSecret {
		t.Fatalf("secret mismatch: %x", cfg.SecretBytes)
	}
}

func TestConfig_ParseSecret_Invalid(t *testing.T) {
	invalids := []string{
		"",
		"123",
		"invalid_non_hex_characters_length_32",
		"ee0123", // too short for ee
		"dd0123", // too short for dd
	}

	for _, inv := range invalids {
		cfg := DefaultConfig()
		if err := cfg.ParseSecret(inv); err == nil {
			t.Fatalf("expected error for invalid secret %q, got nil", inv)
		}
	}
}

func TestConfig_GenerateTelegramProxyLink(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ParseSecret("ee0123456789abcdef0123456789abcdef" + hex.EncodeToString([]byte("google.com")))

	link := cfg.GenerateTelegramProxyLink("0.0.0.0", 0)
	if !strings.HasPrefix(link, "tg://proxy?server=127.0.0.1&port=1443&secret=ee0123456789abcdef0123456789abcdef") {
		t.Fatalf("unexpected link format: %s", link)
	}
	if !strings.Contains(link, hex.EncodeToString([]byte("google.com"))) {
		t.Fatalf("link missing domain hex: %s", link)
	}

	cfg.IsFakeTLS = false
	linkPlain := cfg.GenerateTelegramProxyLink("1.2.3.4", 8443)
	expectedPlain := "tg://proxy?server=1.2.3.4&port=8443&secret=0123456789abcdef0123456789abcdef"
	if linkPlain != expectedPlain {
		t.Fatalf("expected %s, got %s", expectedPlain, linkPlain)
	}
}
