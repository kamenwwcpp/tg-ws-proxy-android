package proto

import (
	"fmt"
	"sync"
)

const (
	HandshakeLen = 64
	SkipLen      = 8
	PrekeyLen    = 32
	KeyLen       = 32
	IVLen        = 16
	ProtoTagPos  = 56
	DCIdxPos     = 60

	ProtoAbridgedInt           uint32 = 0xEFEFEFEF
	ProtoIntermediateInt       uint32 = 0xEEEEEEEE
	ProtoPaddedIntermediateInt uint32 = 0xDDDDDDDD

	WSPath     = "/apiws"
	WSPathTest = "/apiws_test"
)

var (
	ProtoTagAbridged     = [4]byte{0xef, 0xef, 0xef, 0xef}
	ProtoTagIntermediate = [4]byte{0xee, 0xee, 0xee, 0xee}
	ProtoTagSecure       = [4]byte{0xdd, 0xdd, 0xdd, 0xdd}

	ReservedFirstBytes = map[byte]bool{0xEF: true}

	ReservedStarts = map[[4]byte]bool{
		{'H', 'E', 'A', 'D'}: true,
		{'P', 'O', 'S', 'T'}: true,
		{'G', 'E', 'T', ' '}: true,
		{0xee, 0xee, 0xee, 0xee}: true,
		{0xdd, 0xdd, 0xdd, 0xdd}: true,
		{0x16, 0x03, 0x01, 0x02}: true,
		{'O', 'P', 'T', 'I'}: true,
	}

	ReservedContinue = [4]byte{0x00, 0x00, 0x00, 0x00}

	DCDefaultIPs = map[int]string{
		1:   "149.154.175.50",
		2:   "149.154.167.51",
		3:   "149.154.175.100",
		4:   "149.154.167.91",
		5:   "149.154.171.5",
		203: "91.105.192.100",
	}

	DCTestIPs = map[int]string{
		1: "149.154.175.10",
		2: "149.154.167.40",
		3: "149.154.175.117",
	}

	cfDomainsMu sync.RWMutex

	CFDefaultDomains = []string{
		"noskomnadzor.co.uk",
		"cakeisalie.co.uk",
		"fixtelega.co.uk",
		"pclead.co.uk",
		"pomogite.co.uk",
		"havegreatday.co.uk",
		"notelega.co.uk",
		"ebally.co.uk",
		"nebally.co.uk",
		"sadnews.co.uk",
		"stopblocking.co.uk",
		"nothingthere.co.uk",
		"onedaychamp.co.uk",
		"kartoshka.co.uk",
		"sorokodin.co.uk",
		"sorokdva.co.uk",
		"pyatdesyatodin.co.uk",
		"pyatdesyatdva.co.uk",
		"lovetrue.co.uk",
		"offshor.co.uk",
	}
)

// SetCFDomains dynamically updates the list of Cloudflare base gateway domains.
func SetCFDomains(domains []string) {
	cfDomainsMu.Lock()
	defer cfDomainsMu.Unlock()
	CFDefaultDomains = make([]string, len(domains))
	copy(CFDefaultDomains, domains)
}

// GetCFDomains returns a snapshot of the current Cloudflare gateway base domains.
func GetCFDomains() []string {
	cfDomainsMu.RLock()
	defer cfDomainsMu.RUnlock()
	list := make([]string, len(CFDefaultDomains))
	copy(list, CFDefaultDomains)
	return list
}

// WSDomains returns the official Telegram Web gateway domains for a given DC.
func WSDomains(dc int, isMedia bool) []string {
	if dc == 203 {
		dc = 2
	}
	if !isMedia {
		return []string{fmt.Sprintf("kws%d.web.telegram.org", dc)}
	}
	return []string{
		fmt.Sprintf("kws%d-1.web.telegram.org", dc),
		fmt.Sprintf("kws%d.web.telegram.org", dc),
	}
}

// AllUpstreamDomains returns direct domains followed by Cloudflare-proxied gateway domains.
func AllUpstreamDomains(dc int, isMedia bool, useCF bool) []string {
	direct := WSDomains(dc, isMedia)
	if !useCF {
		return direct
	}

	targetDC := dc
	if targetDC == 203 {
		targetDC = 2
	}

	cfBases := GetCFDomains()
	domains := make([]string, 0, len(direct)+len(cfBases))
	domains = append(domains, direct...)

	for _, base := range cfBases {
		domains = append(domains, fmt.Sprintf("kws%d.%s", targetDC, base))
	}
	return domains
}
