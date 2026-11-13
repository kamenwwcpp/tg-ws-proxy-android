package proxy

import (
	"testing"
	"time"
)

func TestBalancer_PrioritizesWorkingDomain(t *testing.T) {
	b := &Balancer{
		working:      make(map[int]string),
		directFailed: make(map[int]time.Time),
	}

	// Cold start should pre-seed with CF domain when useCF is true
	domains := b.GetDomains(2, false, true)
	if len(domains) == 0 {
		t.Fatalf("expected non-empty domains list")
	}
	if domains[0] != "kws2.noskomnadzor.co.uk" {
		t.Errorf("expected first domain to be CF preseed, got %s", domains[0])
	}

	// Record success for another domain
	b.RecordSuccess(2, "kws2.cakeisalie.co.uk")
	domains = b.GetDomains(2, false, true)
	if domains[0] != "kws2.cakeisalie.co.uk" {
		t.Errorf("expected working domain kws2.cakeisalie.co.uk first, got %s", domains[0])
	}

	// Record direct failure
	b.RecordDirectFailure(2)
	b.mu.RLock()
	failedUntil := b.directFailed[2]
	b.mu.RUnlock()
	if time.Now().After(failedUntil) {
		t.Errorf("expected direct failure to be in the future")
	}

	// Verify direct domains are excluded when blocked
	for _, d := range b.GetDomains(2, false, true) {
		if IsDirectDomain(d) {
			t.Errorf("expected direct domain %s to be filtered out while blocked", d)
		}
	}
}
