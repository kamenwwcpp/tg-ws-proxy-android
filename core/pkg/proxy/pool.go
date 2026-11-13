package proxy

import (
	"context"
	"sync"
	"time"

	"tg-ws-proxy-core/pkg/ws"
)

type pooledSocket struct {
	conn  *ws.RawWebSocket
	timer *time.Timer
	stop  func() bool
}

type socketPool struct {
	mu      sync.Mutex
	size    int
	pending map[string]int
	idle    map[string][]*pooledSocket
}

func newSocketPool(size int) *socketPool {
	return &socketPool{size: size, pending: make(map[string]int), idle: make(map[string][]*pooledSocket)}
}

func (p *socketPool) acquire(network context.Context, opts ws.DialOptions) (*ws.RawWebSocket, error) {
	if p.size == 0 {
		return ws.Connect(opts)
	}
	key := opts.Domain + "|" + opts.Host + "|" + opts.Path
	p.mu.Lock()
	var conn *ws.RawWebSocket
	if entries := p.idle[key]; len(entries) > 0 {
		entry := entries[len(entries)-1]
		p.idle[key] = entries[:len(entries)-1]
		entry.timer.Stop()
		entry.stop()
		conn = entry.conn
	}
	p.mu.Unlock()
	if conn == nil {
		var err error
		conn, err = ws.Connect(opts)
		if err != nil {
			return nil, err
		}
	}
	p.mu.Lock()
	if network.Err() == nil && len(p.idle[key])+p.pending[key] < p.size {
		p.pending[key]++
		opts.Context = network
		go p.refill(key, network, opts)
	}
	p.mu.Unlock()
	return conn, nil
}

func (p *socketPool) refill(key string, network context.Context, opts ws.DialOptions) {
	conn, err := ws.Connect(opts)
	p.mu.Lock()
	p.pending[key]--
	if err != nil {
		p.mu.Unlock()
		return
	}
	entry := &pooledSocket{conn: conn}
	expire := func() {
		p.mu.Lock()
		for i, candidate := range p.idle[key] {
			if candidate == entry {
				entries := p.idle[key]
				entries[i] = entries[len(entries)-1]
				p.idle[key] = entries[:len(entries)-1]
				entry.timer.Stop()
				entry.stop()
				p.mu.Unlock()
				_ = conn.Close()
				return
			}
		}
		p.mu.Unlock()
	}
	entry.timer = time.AfterFunc(30*time.Second, expire)
	entry.stop = context.AfterFunc(network, expire)
	p.idle[key] = append(p.idle[key], entry)
	p.mu.Unlock()
}
