package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"tg-ws-proxy-core/pkg/config"
	"tg-ws-proxy-core/pkg/crypto"
	"tg-ws-proxy-core/pkg/faketls"
	"tg-ws-proxy-core/pkg/proto"
	"tg-ws-proxy-core/pkg/relay"
	"tg-ws-proxy-core/pkg/ws"
)

// Server coordinates listening for client connections, authentication, and routing to Telegram.
type routeKey struct {
	network, dc int
	media       bool
}

type Server struct {
	cfg         *config.Config
	mu          sync.Mutex
	available   bool
	kind        int
	network     context.Context
	stopNetwork context.CancelFunc
	routes      map[routeKey]*Balancer
	pools       *socketPool
}

func NewServer(cfg *config.Config) *Server {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{cfg: cfg, available: true, network: ctx, stopNetwork: cancel, routes: make(map[routeKey]*Balancer), pools: newSocketPool(cfg.PoolSize)}
}

func (s *Server) SetNetwork(available bool, kind int, reset bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if reset || available != s.available || kind != s.kind {
		s.stopNetwork()
		s.network, s.stopNetwork = context.WithCancel(context.Background())
		s.pools = newSocketPool(s.cfg.PoolSize)
	}
	s.available, s.kind = available, kind
}

func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}

// Serve takes ownership of a listener that has already bound successfully.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	defer s.shutdownNetwork()
	var clients sync.WaitGroup
	defer clients.Wait()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		s.mu.Lock()
		available, network := s.available, s.network
		s.mu.Unlock()
		if !available {
			_ = conn.Close()
			continue
		}
		clients.Add(1)
		go func() {
			defer clients.Done()
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			stopNetwork := context.AfterFunc(network, cancel)
			defer stopNetwork()
			stopConn := context.AfterFunc(ctx, func() { _ = conn.Close() })
			defer stopConn()
			s.handleClient(ctx, conn)
		}()
	}
}

func (s *Server) handleClient(ctx context.Context, rawConn net.Conn) {
	relay.GlobalStats.IncConnectionsTotal()
	relay.GlobalStats.IncConnectionsActive()
	defer relay.GlobalStats.DecConnectionsActive()
	defer rawConn.Close()

	if tc, ok := rawConn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetReadBuffer(s.cfg.BufferSize)
		_ = tc.SetWriteBuffer(s.cfg.BufferSize)
	}

	// Read initial byte
	var firstByte [1]byte
	_ = rawConn.SetDeadline(time.Now().Add(s.cfg.Timeout))
	if _, err := io.ReadFull(rawConn, firstByte[:]); err != nil {
		return
	}

	var clientConn net.Conn = rawConn
	var handshake [proto.HandshakeLen]byte

	if firstByte[0] == faketls.TLSRecordHandshake && s.cfg.IsFakeTLS {
		// Fake TLS ClientHello flow
		var hdrRest [4]byte
		if _, err := io.ReadFull(rawConn, hdrRest[:]); err != nil {
			return
		}
		recordLen := binary.BigEndian.Uint16(hdrRest[2:4])
		recordBody := make([]byte, recordLen)
		if _, err := io.ReadFull(rawConn, recordBody); err != nil {
			return
		}

		clientHello := make([]byte, 5+recordLen)
		clientHello[0] = firstByte[0]
		copy(clientHello[1:5], hdrRest[:])
		copy(clientHello[5:], recordBody)

		info, err := faketls.VerifyClientHello(clientHello, s.cfg.SecretBytes)
		if err != nil {
			logFakeTLSFailure()
			redirect := fmt.Sprintf("HTTP/1.1 301 Moved Permanently\r\nLocation: https://%s/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", s.cfg.FakeTLSDomain)
			_, _ = rawConn.Write([]byte(redirect))
			return
		}

		serverHello, err := faketls.BuildServerHello(s.cfg.SecretBytes, info.ClientRandom, info.SessionID)
		if err != nil {
			log.Printf("[Proxy] BuildServerHello failed: %v", err)
			return
		}

		if _, err := rawConn.Write(serverHello); err != nil {
			return
		}

		fakeConn := faketls.NewFakeTLSConn(rawConn)
		clientConn = fakeConn

		_ = rawConn.SetDeadline(time.Now().Add(s.cfg.Timeout))
		if _, err := io.ReadFull(fakeConn, handshake[:]); err != nil {
			log.Printf("[Proxy] Failed to read MTProto init inside TLS: %v", err)
			return
		}
	} else if s.cfg.IsFakeTLS {
		// Client connected with non-TLS byte while Fake TLS is enforced
		redirect := fmt.Sprintf("HTTP/1.1 301 Moved Permanently\r\nLocation: https://%s/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", s.cfg.FakeTLSDomain)
		_, _ = rawConn.Write([]byte(redirect))
		return
	} else {
		// Raw MTProto
		handshake[0] = firstByte[0]
		if _, err := io.ReadFull(rawConn, handshake[1:]); err != nil {
			return
		}
	}

	_ = rawConn.SetDeadline(time.Time{})
	_ = clientConn.SetDeadline(time.Time{})

	// Parse MTProto handshake
	res, err := crypto.TryHandshake(handshake[:], s.cfg.SecretBytes)
	if err != nil {
		relay.GlobalStats.IncConnectionsBad()
		_ = rawConn.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, _ = io.CopyN(io.Discard, clientConn, 64*1024)
		return
	}

	dcID := res.DCID
	isMedia := res.IsMedia
	if s.cfg.ForceTestDC || dcID >= 10000 {
		if dcID >= 10000 {
			dcID -= 10000
		}
	}

	if _, known := proto.DCDefaultIPs[dcID]; !known {
		return
	}

	dcIdx := int16(dcID)
	if isMedia {
		dcIdx = -dcIdx
	}

	relayInit, err := crypto.GenerateRelayInit(res.ProtoTag, dcIdx)
	if err != nil {
		log.Printf("[Proxy] Failed to generate relay init: %v", err)
		return
	}

	cryptoCtx, err := crypto.NewCryptoContext(res.ClientDecPrekeyIV, s.cfg.SecretBytes, relayInit)
	if err != nil {
		log.Printf("[Proxy] Failed to derive crypto context: %v", err)
		return
	}

	splitter := proto.NewMsgSplitter(res.ProtoInt)

	kind := "chat"
	if isMedia {
		kind = "media"
	}

	// Fast concurrent upstream connection with staggered Happy-Eyeballs dialing
	upstreamWS, activeDomain, lastErr := s.dialFastUpstream(ctx, dcID, isMedia)
	if upstreamWS != nil {
		relay.GlobalStats.IncConnectionsWS()
		logConnected(dcID, isMedia, activeDomain)
		if err := upstreamWS.Send(relayInit); err != nil {
			_ = upstreamWS.Close()
			return
		}
		relay.BridgeWS(ctx, clientConn, upstreamWS, cryptoCtx, splitter, relay.GlobalStats, dcID, isMedia)
		return
	}

	// Fallback to Cloudflare Worker if direct and CF pool are unavailable
	if s.cfg.FallbackCF && len(s.cfg.CFWorkerDomains) > 0 {
		defaultIP := proto.DCDefaultIPs[dcID]
		workerTimeout := 4 * time.Second
		if s.cfg.Timeout < workerTimeout {
			workerTimeout = s.cfg.Timeout
		}
		for _, workerDomain := range s.cfg.CFWorkerDomains {
			workerPath := fmt.Sprintf("/apiws?dst=%s&dc=%d", defaultIP, dcID)
			wsConn, err := ws.Connect(ws.DialOptions{
				Host:       workerDomain,
				Domain:     workerDomain,
				Path:       workerPath,
				Secure:     true,
				Timeout:    workerTimeout,
				BufferSize: s.cfg.BufferSize,
			})
			if err == nil {
				relay.GlobalStats.IncConnectionsFallback()
				logConnected(dcID, isMedia, "CF Worker "+workerDomain)
				if err := wsConn.Send(relayInit); err != nil {
					_ = wsConn.Close()
					return
				}
				relay.BridgeWS(ctx, clientConn, wsConn, cryptoCtx, splitter, relay.GlobalStats, dcID, isMedia)
				return
			} else {
				lastErr = err
			}
		}
	}

	logUnreachable(dcID, kind, lastErr)
}

var (
	unreachableLogMu   sync.Mutex
	lastUnreachableLog time.Time
)

func logUnreachable(dcID int, kind string, err error) {
	unreachableLogMu.Lock()
	defer unreachableLogMu.Unlock()
	now := time.Now()
	if now.Sub(lastUnreachableLog) >= 5*time.Second {
		lastUnreachableLog = now
		log.Printf("[Proxy] DC%d (%s) unreachable: %v", dcID, kind, err)
	}
}

var (
	fakeTLSLogMu   sync.Mutex
	lastFakeTLSLog time.Time
)

func logFakeTLSFailure() {
	fakeTLSLogMu.Lock()
	defer fakeTLSLogMu.Unlock()
	now := time.Now()
	if now.Sub(lastFakeTLSLog) >= 5*time.Second {
		lastFakeTLSLog = now
		log.Printf("[Proxy] Fake TLS verify failed: secret mismatch -> redirecting")
	}
}

var (
	connLogMu    sync.Mutex
	lastChatLog  = make(map[int]time.Time)
	lastMediaLog = make(map[int]time.Time)
)

func logConnected(dcID int, isMedia bool, domain string) {
	connLogMu.Lock()
	defer connLogMu.Unlock()
	now := time.Now()
	if isMedia {
		if now.Sub(lastMediaLog[dcID]) >= 60*time.Second {
			lastMediaLog[dcID] = now
			log.Printf("[Proxy] Connected DC%d (media) via %s", dcID, domain)
		}
	} else {
		if now.Sub(lastChatLog[dcID]) >= 30*time.Second {
			lastChatLog[dcID] = now
			log.Printf("[Proxy] Connected DC%d (chat) via %s", dcID, domain)
		}
	}
}

type dialResult struct {
	ws     *ws.RawWebSocket
	domain string
	err    error
	index  int
}

func (s *Server) DialFastUpstreamForTest(ctx context.Context, dcID int, isMedia bool) (*ws.RawWebSocket, string, error) {
	return s.dialFastUpstream(ctx, dcID, isMedia)
}

// dialFastUpstream initiates concurrent staggered Happy-Eyeballs connection attempts
// to upstream gateways to prevent waiting on sequentially failing domains.
func (s *Server) dialFastUpstream(parentCtx context.Context, dcID int, isMedia bool) (*ws.RawWebSocket, string, error) {
	s.mu.Lock()
	key := routeKey{s.kind, dcID, isMedia}
	balancer := s.routes[key]
	if balancer == nil {
		balancer = newBalancer()
		s.routes[key] = balancer
	}
	pool := s.pools
	kind := s.kind
	network := s.network
	s.mu.Unlock()
	domains := balancer.domains(dcID, isMedia, s.cfg.FallbackCF, s.cfg.CFPriority && kind == 2)
	if len(domains) == 0 {
		return nil, "", errors.New("no upstream domains available")
	}

	// Limit to top 6 candidates to avoid socket churn
	if len(domains) > 6 {
		domains = domains[:6]
	}

	resultCh := make(chan dialResult, len(domains))
	cancels := make([]context.CancelFunc, len(domains))
	var cancelsMu sync.Mutex
	var candidateWg sync.WaitGroup

	defer func() {
		cancelsMu.Lock()
		for _, c := range cancels {
			if c != nil {
				c()
			}
		}
		cancelsMu.Unlock()
	}()

	activeCount := 0
	candidateIdx := 0

	launchCandidate := func(idx int) {
		if idx >= len(domains) {
			return
		}
		domain := domains[idx]
		candCtx, cancel := context.WithCancel(parentCtx)

		cancelsMu.Lock()
		cancels[idx] = cancel
		cancelsMu.Unlock()

		activeCount++
		candidateWg.Add(1)
		go func(d string, i int, cCtx context.Context, cCancel context.CancelFunc) {
			defer candidateWg.Done()
			domainTimeout := 4 * time.Second
			if IsDirectDomain(d) {
				domainTimeout = 1500 * time.Millisecond
			}
			if s.cfg.Timeout < domainTimeout {
				domainTimeout = s.cfg.Timeout
			}

			wsConn, err := pool.acquire(network, ws.DialOptions{
				Context:    cCtx,
				Host:       s.cfg.DirectHost(dcID, isMedia, d),
				Domain:     d,
				Path:       proto.WSPath,
				Secure:     true,
				Timeout:    domainTimeout,
				BufferSize: s.cfg.BufferSize,
			})

			if cCtx.Err() != nil {
				if wsConn != nil {
					_ = wsConn.Close()
				}
				cCancel()
				return
			}

			resultCh <- dialResult{ws: wsConn, domain: d, err: err, index: i}
		}(domain, idx, candCtx, cancel)
	}

	// Start first candidate immediately
	launchCandidate(0)
	candidateIdx = 1

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	var lastErr error

	for {
		select {
		case <-parentCtx.Done():
			cancelsMu.Lock()
			for _, c := range cancels {
				if c != nil {
					c()
				}
			}
			cancelsMu.Unlock()
			go func() {
				candidateWg.Wait()
				for len(resultCh) > 0 {
					extra := <-resultCh
					if extra.ws != nil {
						_ = extra.ws.Close()
					}
				}
			}()
			return nil, "", parentCtx.Err()

		case <-ticker.C:
			// Stagger next dial if candidates remain and we have room for concurrency
			if candidateIdx < len(domains) && activeCount < 3 {
				launchCandidate(candidateIdx)
				candidateIdx++
			}

		case res := <-resultCh:
			activeCount--
			if res.err == nil && res.ws != nil {
				cancelsMu.Lock()
				for _, c := range cancels {
					if c != nil {
						c()
					}
				}
				cancelsMu.Unlock()

				if parentCtx.Err() == nil {
					balancer.RecordSuccess(dcID, res.domain)
				}

				// Deterministic background drain for excess connections
				go func(winnerIndex int) {
					done := make(chan struct{})
					go func() {
						candidateWg.Wait()
						close(done)
					}()

					for {
						select {
						case extra := <-resultCh:
							if extra.index != winnerIndex && extra.ws != nil {
								_ = extra.ws.Close()
							}
						case <-done:
							for len(resultCh) > 0 {
								extra := <-resultCh
								if extra.index != winnerIndex && extra.ws != nil {
									_ = extra.ws.Close()
								}
							}
							return
						}
					}
				}(res.index)

				return res.ws, res.domain, nil
			}

			lastErr = res.err
			if IsDirectDomain(res.domain) && parentCtx.Err() == nil {
				if kind == 2 {
					balancer.recordDirectFailure(dcID, 5*time.Minute)
				}
			}

			// If candidate failed early, trigger next candidate immediately
			if candidateIdx < len(domains) {
				launchCandidate(candidateIdx)
				candidateIdx++
			} else if activeCount == 0 {
				if lastErr == nil {
					lastErr = errors.New("all upstream dials failed")
				}
				return nil, "", lastErr
			}
		}
	}
}

func (s *Server) shutdownNetwork() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopNetwork()
}
