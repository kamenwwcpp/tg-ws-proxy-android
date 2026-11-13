package proxy

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"tg-ws-proxy-core/pkg/proto"
)

// Balancer caches working domains for each DC and remembers blocked direct endpoints.
type Balancer struct {
	mu           sync.RWMutex
	working      map[int]string
	directFailed map[int]time.Time
}

func newBalancer() *Balancer {
	return &Balancer{working: make(map[int]string), directFailed: make(map[int]time.Time)}
}

// GetDomains returns domain candidates for a DC with the last known working domain first.
func (b *Balancer) GetDomains(dcID int, isMedia bool, useCF bool) []string {
	return b.domains(dcID, isMedia, useCF, true)
}

func (b *Balancer) domains(dcID int, isMedia, useCF, cfFirst bool) []string {
	b.mu.RLock()
	workingDomain := b.working[dcID]
	failedUntil := b.directFailed[dcID]
	b.mu.RUnlock()

	var domains []string
	seen := make(map[string]bool)

	// 1. Prioritize the last successfully used domain for this DC (or pre-seed with CF if fallback enabled)
	if (IsDirectDomain(workingDomain) && time.Now().Before(failedUntil)) || (!useCF && !IsDirectDomain(workingDomain)) {
		workingDomain = ""
	}
	if workingDomain == "" && useCF && cfFirst {
		targetDC := dcID
		if targetDC == 203 {
			targetDC = 2
		}
		cfList := proto.GetCFDomains()
		if len(cfList) > 0 {
			workingDomain = fmt.Sprintf("kws%d.%s", targetDC, cfList[0])
		}
	}

	if workingDomain != "" {
		domains = append(domains, workingDomain)
		seen[workingDomain] = true
	}

	// 2. Direct domains (only if not currently marked as blocked)
	directBlocked := time.Now().Before(failedUntil)
	if !directBlocked {
		for _, d := range proto.WSDomains(dcID, isMedia) {
			if !seen[d] {
				domains = append(domains, d)
				seen[d] = true
			}
		}
	}

	// 3. Cloudflare fallback pool
	if useCF {
		targetDC := dcID
		if targetDC == 203 {
			targetDC = 2
		}
		for _, base := range proto.GetCFDomains() {
			candidate := fmt.Sprintf("kws%d.%s", targetDC, base)
			if !seen[candidate] {
				domains = append(domains, candidate)
				seen[candidate] = true
			}
		}
	}

	return domains
}

// RecordSuccess marks domain as the primary active gateway for this DC.
func (b *Balancer) RecordSuccess(dcID int, domain string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.working[dcID] = domain
	if IsDirectDomain(domain) {
		delete(b.directFailed, dcID)
	}
}

// RecordDirectFailure backs off direct web.telegram.org domains for 10 minutes.
func (b *Balancer) RecordDirectFailure(dcID int) {
	b.recordDirectFailure(dcID, 10*time.Minute)
}

// IsDirectDomain returns true if domain is an official web.telegram.org domain.
func IsDirectDomain(domain string) bool {
	return strings.HasSuffix(domain, ".web.telegram.org")
}

func (b *Balancer) recordDirectFailure(dcID int, wait time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.directFailed[dcID] = time.Now().Add(wait)
}
