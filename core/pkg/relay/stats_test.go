package relay

import (
	"sync"
	"testing"
)

func TestStats_ConcurrentOperations(t *testing.T) {
	s := &Stats{}
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.AddBytesUp(1024)
			s.AddBytesDown(2048)
			s.IncConnectionsTotal()
			s.IncConnectionsActive()
			s.DecConnectionsActive()
			s.IncConnectionsWS()
			s.IncConnectionsFallback()
			s.IncConnectionsBad()
		}()
	}

	wg.Wait()
	snap := s.Snapshot()

	if snap.BytesUp != 100*1024 {
		t.Fatalf("unexpected BytesUp: %d", snap.BytesUp)
	}
	if snap.BytesDown != 100*2048 {
		t.Fatalf("unexpected BytesDown: %d", snap.BytesDown)
	}
	if snap.ConnectionsTotal != 100 {
		t.Fatalf("unexpected ConnectionsTotal: %d", snap.ConnectionsTotal)
	}
	if snap.ConnectionsActive != 0 {
		t.Fatalf("unexpected ConnectionsActive: %d", snap.ConnectionsActive)
	}
	if snap.ConnectionsWS != 100 || snap.ConnectionsFallback != 100 || snap.ConnectionsBad != 100 {
		t.Fatalf("unexpected counts in snapshot: %+v", snap)
	}
}
