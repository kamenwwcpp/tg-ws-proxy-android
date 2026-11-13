package relay

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"tg-ws-proxy-core/pkg/crypto"
	"tg-ws-proxy-core/pkg/proto"
	"tg-ws-proxy-core/pkg/ws"
)

// BridgeWS manages bidirectional re-encrypting pipe between MTProto client and Telegram WebSocket.
func BridgeWS(
	ctx context.Context,
	client net.Conn,
	remoteWS *ws.RawWebSocket,
	cryptoCtx *crypto.CryptoContext,
	splitter *proto.MsgSplitter,
	stats *Stats,
	dcID int,
	isMedia bool,
) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	// Only send a keepalive after an idle interval.
	const keepaliveInterval = 120 * time.Second
	started := time.Now()
	var lastActivity atomic.Int64
	go func() {
		ticker := time.NewTicker(keepaliveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if time.Since(started)-time.Duration(lastActivity.Load()) < keepaliveInterval {
					continue
				}
				if err := remoteWS.Ping(); err != nil {
					cancel()
					return
				}
			}
		}
	}()

	// Client -> WebSocket
	go func() {
		defer wg.Done()
		defer cancel()

		buf := make([]byte, 65536)
		var plainBuf []byte
		if splitter != nil {
			plainBuf = make([]byte, 65536)
		}

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			n, err := client.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				lastActivity.Store(int64(time.Since(started)))
				stats.AddBytesUp(n)

				if splitter != nil {
					plain := plainBuf[:n]
					cryptoCtx.CltDec.XORKeyStream(plain, chunk)
					cryptoCtx.TgEnc.XORKeyStream(chunk, plain)

					parts := splitter.Split(chunk, plain)
					if len(parts) > 1 {
						if err := remoteWS.SendBatch(parts); err != nil {
							return
						}
					} else if len(parts) == 1 {
						if err := remoteWS.Send(parts[0]); err != nil {
							return
						}
					}
				} else {
					cryptoCtx.CltDec.XORKeyStream(chunk, chunk)
					cryptoCtx.TgEnc.XORKeyStream(chunk, chunk)
					if err := remoteWS.Send(chunk); err != nil {
						return
					}
				}
			}

			if err != nil {
				if err != io.EOF {
					// Client closed or reset
				}
				if splitter != nil {
					tail := splitter.Flush()
					if len(tail) > 0 {
						_ = remoteWS.Send(tail[0])
					}
				}
				return
			}
		}
	}()

	// WebSocket -> Client
	go func() {
		defer wg.Done()
		defer cancel()

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			data, err := remoteWS.Recv()
			if err != nil {
				return
			}

			n := len(data)
			lastActivity.Store(int64(time.Since(started)))
			stats.AddBytesDown(n)

			// In-place dual CTR stream decrypt and re-encrypt directly in data buffer
			cryptoCtx.TgDec.XORKeyStream(data, data)
			cryptoCtx.CltEnc.XORKeyStream(data, data)

			if _, err := client.Write(data); err != nil {
				return
			}
		}
	}()

	<-ctx.Done()
	_ = client.Close()
	_ = remoteWS.Close()
	wg.Wait()
}

// FormatBytes formats byte counts into human-readable B, KB, or MB units.
func FormatBytes(b uint64) string {
	if b < 1024 {
		return fmt.Sprintf("%d B", b)
	} else if b < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(b)/1024.0)
	}
	return fmt.Sprintf("%.2f MB", float64(b)/(1024.0*1024.0))
}
