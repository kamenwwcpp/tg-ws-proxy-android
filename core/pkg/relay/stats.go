package relay

import (
	"sync/atomic"
)

// Stats tracks aggregate network statistics across proxy sessions.
// All 64-bit integer fields are naturally 64-bit aligned when allocated on heap.
type Stats struct {
	BytesUp             uint64
	BytesDown           uint64
	ConnectionsTotal    uint64
	ConnectionsActive   int64
	ConnectionsBad      uint64
	ConnectionsWS       uint64
	ConnectionsFallback uint64
}

// StatsSnapshot provides an alias to Stats for backward compatibility.
type StatsSnapshot = Stats

var GlobalStats = &Stats{}

func (s *Stats) AddBytesUp(n int) {
	atomic.AddUint64(&s.BytesUp, uint64(n))
}

func (s *Stats) AddBytesDown(n int) {
	atomic.AddUint64(&s.BytesDown, uint64(n))
}

func (s *Stats) IncConnectionsTotal() {
	atomic.AddUint64(&s.ConnectionsTotal, 1)
}

func (s *Stats) IncConnectionsActive() {
	atomic.AddInt64(&s.ConnectionsActive, 1)
}

func (s *Stats) DecConnectionsActive() {
	atomic.AddInt64(&s.ConnectionsActive, -1)
}

func (s *Stats) IncConnectionsBad() {
	atomic.AddUint64(&s.ConnectionsBad, 1)
}

func (s *Stats) IncConnectionsWS() {
	atomic.AddUint64(&s.ConnectionsWS, 1)
}

func (s *Stats) IncConnectionsFallback() {
	atomic.AddUint64(&s.ConnectionsFallback, 1)
}

// Snapshot returns a point-in-time copy of current stats.
func (s *Stats) Snapshot() Stats {
	return Stats{
		BytesUp:             atomic.LoadUint64(&s.BytesUp),
		BytesDown:           atomic.LoadUint64(&s.BytesDown),
		ConnectionsTotal:    atomic.LoadUint64(&s.ConnectionsTotal),
		ConnectionsActive:   atomic.LoadInt64(&s.ConnectionsActive),
		ConnectionsBad:      atomic.LoadUint64(&s.ConnectionsBad),
		ConnectionsWS:       atomic.LoadUint64(&s.ConnectionsWS),
		ConnectionsFallback: atomic.LoadUint64(&s.ConnectionsFallback),
	}
}
