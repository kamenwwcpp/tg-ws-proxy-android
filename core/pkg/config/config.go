package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

var (
	ErrInvalidSecret = errors.New("invalid secret format (must be 32 hex characters or ee... Fake TLS format)")
)

// Config represents proxy configuration settings.
type Config struct {
	PoolSize        int
	CFPriority      bool
	DirectIPs       map[int]string
	ListenAddr      string
	RawSecretHex    string
	SecretBytes     []byte
	FakeTLSDomain   string
	IsFakeTLS       bool
	FallbackCF      bool
	CFWorkerDomains []string
	BufferSize      int
	Timeout         time.Duration
	ForceTestDC     bool
}

// DefaultConfig returns reasonable defaults.
func DefaultConfig() *Config {
	defaultSecret := "00000000000000000000000000000000"
	secBytes, _ := hex.DecodeString(defaultSecret)
	return &Config{
		ListenAddr:    "127.0.0.1:1443",
		RawSecretHex:  defaultSecret,
		SecretBytes:   secBytes,
		FakeTLSDomain: "google.com",
		IsFakeTLS:     true,
		FallbackCF:    true,
		BufferSize:    65536,
		Timeout:       10 * time.Second,
	}
}

// ParseSecret parses raw secret string which can be plain 32-hex, or Fake TLS (ee + 32-hex + domain_hex).
func (c *Config) ParseSecret(secretStr string) error {
	secretStr = strings.TrimSpace(secretStr)
	c.RawSecretHex = secretStr

	// Check for Fake TLS prefix 'ee'
	if strings.HasPrefix(strings.ToLower(secretStr), "ee") && len(secretStr) >= 34 {
		c.IsFakeTLS = true
		rawHex := secretStr[2:34]
		sec, err := hex.DecodeString(rawHex)
		if err != nil {
			return ErrInvalidSecret
		}
		c.SecretBytes = sec

		if len(secretStr) > 34 {
			domainHex := secretStr[34:]
			domainBytes, err := hex.DecodeString(domainHex)
			if err == nil && len(domainBytes) > 0 {
				c.FakeTLSDomain = string(domainBytes)
			}
		}
		return nil
	}

	// Check for 'dd' prefix (secure/padded)
	if strings.HasPrefix(strings.ToLower(secretStr), "dd") && len(secretStr) == 34 {
		sec, err := hex.DecodeString(secretStr[2:])
		if err != nil {
			return ErrInvalidSecret
		}
		c.SecretBytes = sec
		c.IsFakeTLS = false
		return nil
	}

	// Standard 16-byte hex secret
	if len(secretStr) == 32 {
		sec, err := hex.DecodeString(secretStr)
		if err != nil {
			return ErrInvalidSecret
		}
		c.SecretBytes = sec
		return nil
	}

	return ErrInvalidSecret
}

// GenerateTelegramProxyLink builds the tg://proxy URI for one-click connection.
func (c *Config) GenerateTelegramProxyLink(host string, port int) string {
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	if port <= 0 {
		port = 1443
	}

	var secretParam string
	if c.IsFakeTLS && c.FakeTLSDomain != "" {
		secretParam = "ee" + hex.EncodeToString(c.SecretBytes) + hex.EncodeToString([]byte(c.FakeTLSDomain))
	} else {
		secretParam = hex.EncodeToString(c.SecretBytes)
	}

	return fmt.Sprintf("tg://proxy?server=%s&port=%d&secret=%s", host, port, secretParam)
}

func (c *Config) DirectHost(dc int, media bool, domain string) string {
	if !strings.HasSuffix(domain, ".web.telegram.org") {
		return domain
	}
	if media && net.ParseIP(c.DirectIPs[-dc]) != nil {
		return c.DirectIPs[-dc]
	}
	if net.ParseIP(c.DirectIPs[dc]) != nil {
		return c.DirectIPs[dc]
	}
	return domain
}
