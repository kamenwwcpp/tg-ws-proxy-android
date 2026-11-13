//go:build android && cgo

package main

/*
#include <stdlib.h>
#include <android/log.h>
#cgo LDFLAGS: -llog
static void proxyLog(const char *msg) {
	__android_log_write(ANDROID_LOG_INFO, "TgWsProxy", msg);
}
*/
import "C"

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"tg-ws-proxy-core/pkg/config"
	"tg-ws-proxy-core/pkg/proto"
	"tg-ws-proxy-core/pkg/proxy"
	"tg-ws-proxy-core/pkg/relay"
)

type androidLogger struct{}

func (androidLogger) Write(p []byte) (int, error) {
	message := C.CString(strings.TrimRight(string(p), "\r\n"))
	C.proxyLog(message)
	C.free(unsafe.Pointer(message))
	return len(p), nil
}

var state struct {
	sync.Mutex
	server     *proxy.Server
	cancel     context.CancelFunc
	done       chan struct{}
	available  bool
	kind       int
	poolSize   int
	cfEnabled  bool
	cfPriority bool
	cfDomain   string
}

var defaultDomains = proto.GetCFDomains()

func init() {
	if _, err := os.Stat("/apex/com.android.conscrypt/cacerts"); err == nil {
		if _, set := os.LookupEnv("SSL_CERT_DIR"); !set {
			_ = os.Setenv("SSL_CERT_DIR", "/apex/com.android.conscrypt/cacerts:/system/etc/security/cacerts")
		}
	}
	state.available = true
	state.poolSize = 4
	state.cfEnabled = true
	log.SetOutput(androidLogger{})
	log.SetFlags(0)
}

//export StartProxy
func StartProxy(host *C.char, port C.int, ips, secret *C.char, verbose C.int) C.int {
	state.Lock()
	defer state.Unlock()
	if state.server != nil {
		return -1
	}
	if port < 1 || port > 65535 {
		return -2
	}
	cfg := config.DefaultConfig()
	cfg.IsFakeTLS = false
	cfg.ListenAddr = net.JoinHostPort(C.GoString(host), strconv.Itoa(int(port)))
	if err := cfg.ParseSecret(C.GoString(secret)); err != nil {
		return -2
	}
	cfg.FallbackCF = state.cfEnabled
	cfg.CFPriority = state.cfPriority
	cfg.PoolSize = state.poolSize
	cfg.DirectIPs = make(map[int]string)
	for _, value := range strings.Split(C.GoString(ips), ",") {
		dc, ip, ok := strings.Cut(value, ":")
		id, err := strconv.Atoi(strings.TrimSpace(dc))
		ip = strings.TrimSpace(ip)
		if ok && err == nil && net.ParseIP(ip) != nil {
			cfg.DirectIPs[id] = ip
		}
	}
	domains := defaultDomains
	if state.cfDomain != "" {
		domains = append([]string{state.cfDomain}, defaultDomains...)
	}
	proto.SetCFDomains(domains)
	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Printf("[ERROR] %v", err)
		return -3
	}
	server := proxy.NewServer(cfg)
	server.SetNetwork(state.available, state.kind, false)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	state.server, state.cancel, state.done = server, cancel, done
	go func() {
		defer close(done)
		if err := server.Serve(ctx, ln); err != nil {
			log.Printf("[ERROR] %v", err)
		}
	}()
	return 0
}

//export StopProxy
func StopProxy() C.int {
	state.Lock()
	defer state.Unlock()
	if state.server == nil {
		return 0
	}
	state.cancel()
	<-state.done
	state.server = nil
	return 0
}

//export SetNetworkState
func SetNetworkState(available, kind C.int) C.int {
	state.Lock()
	defer state.Unlock()
	state.available, state.kind = available != 0, int(kind)
	if state.server != nil {
		state.server.SetNetwork(state.available, state.kind, false)
	}
	return 0
}

//export NetworkChanged
func NetworkChanged() C.int {
	state.Lock()
	defer state.Unlock()
	if state.server != nil {
		state.server.SetNetwork(state.available, state.kind, true)
	}
	return 0
}

//export SetPoolSize
func SetPoolSize(size C.int) {
	state.Lock()
	defer state.Unlock()
	state.poolSize = min(16, max(0, int(size)))
}

//export SetCfProxyConfig
func SetCfProxyConfig(enabled, priority C.int, domain *C.char) {
	state.Lock()
	defer state.Unlock()
	state.cfEnabled, state.cfPriority = enabled != 0, priority != 0
	state.cfDomain = strings.Trim(strings.TrimSpace(C.GoString(domain)), ".")
	if !validDomain(state.cfDomain) {
		state.cfDomain = ""
	}
}

func validDomain(domain string) bool {
	if len(domain) > 253 {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range strings.ToLower(label) {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

//export GetStats
func GetStats() *C.char {
	s := relay.GlobalStats.Snapshot()
	return C.CString(fmt.Sprintf("active=%d up=%dB down=%dB", s.ConnectionsActive, s.BytesUp, s.BytesDown))
}

//export FreeString
func FreeString(p *C.char) { C.free(unsafe.Pointer(p)) }

func main() {}
