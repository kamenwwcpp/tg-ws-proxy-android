package main

import (
	"context"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"tg-ws-proxy-core/pkg/config"
	"tg-ws-proxy-core/pkg/proto"
	"tg-ws-proxy-core/pkg/proxy"
	"tg-ws-proxy-core/pkg/relay"
)

func main() {
	listenFlag := flag.String("listen", "127.0.0.1:1443", "Address to listen on (e.g. 127.0.0.1:1443)")
	secretFlag := flag.String("secret", "", "Proxy secret (plain hex or ee<secret><domain>)")
	domainFlag := flag.String("domain", "google.com", "Masking domain for Fake TLS")
	cfWorkerFlag := flag.String("cf-worker", "", "Comma-separated Cloudflare worker domains for fallback")
	cfDomainsFlag := flag.String("cf-domains", "", "Comma-separated Cloudflare proxy base domains")
	noFakeTLSFlag := flag.Bool("no-faketls", false, "Disable Fake TLS (use raw MTProto obfuscation)")
	statsIntervalFlag := flag.Int("stats-interval", 15, "Seconds between stats logs (0 to disable)")

	noCFFlag := flag.Bool("no-cf", false, "Disable Cloudflare fallback")
	secretStdin := flag.Bool("secret-stdin", false, "Read secret from standard input")
	flag.Parse()
	if *secretStdin {
		secret, err := io.ReadAll(io.LimitReader(os.Stdin, 1025))
		if err != nil || len(secret) > 1024 {
			log.Fatal("Could not read proxy secret")
		}
		*secretFlag = strings.TrimSpace(string(secret))
	}
	if *secretFlag == "" {
		log.Fatal("A proxy secret is required")
	}

	if *cfDomainsFlag != "" {
		var list []string
		for _, d := range strings.Split(*cfDomainsFlag, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				list = append(list, d)
			}
		}
		if len(list) > 0 {
			proto.SetCFDomains(list)
			log.Printf("[Proxy] Loaded %d CF gateway mirrors", len(list))
		}
	}

	cfg := config.DefaultConfig()
	cfg.ListenAddr = *listenFlag
	cfg.FallbackCF = !*noCFFlag
	cfg.FakeTLSDomain = *domainFlag
	cfg.IsFakeTLS = !*noFakeTLSFlag

	if *secretFlag != "" {
		if err := cfg.ParseSecret(*secretFlag); err != nil {
			log.Fatalf("Invalid secret provided: %v", err)
		}
	}

	if *cfWorkerFlag != "" {
		for _, w := range strings.Split(*cfWorkerFlag, ",") {
			w = strings.TrimSpace(w)
			if w != "" {
				cfg.CFWorkerDomains = append(cfg.CFWorkerDomains, w)
			}
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := proxy.NewServer(cfg)

	// Periodic stats printer
	if *statsIntervalFlag > 0 {
		go func() {
			ticker := time.NewTicker(time.Duration(*statsIntervalFlag) * time.Second)
			defer ticker.Stop()
			var previous relay.Stats
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					snap := relay.GlobalStats.Snapshot()
					if snap != previous {
						previous = snap
						log.Printf("[Stats] Active: %d | Total: %d (WS: %d, FB: %d, Bad: %d) | Up: %.2f MB | Down: %.2f MB",
							snap.ConnectionsActive, snap.ConnectionsTotal,
							snap.ConnectionsWS, snap.ConnectionsFallback, snap.ConnectionsBad,
							float64(snap.BytesUp)/1048576.0, float64(snap.BytesDown)/1048576.0)
					}
				}
			}
		}()
	}

	if err := srv.Start(ctx); err != nil {
		log.Fatalf("Proxy server failed: %v", err)
	}

	log.Println("[Proxy] Server shutdown cleanly.")
}
