package relay

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"tg-ws-proxy-core/pkg/crypto"
	"tg-ws-proxy-core/pkg/proto"
	"tg-ws-proxy-core/pkg/ws"
)

func TestBridgeClosesBlockedConnections(t *testing.T) {
	for _, trigger := range []string{"cancel", "client", "upstream"} {
		t.Run(trigger, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			accepted := make(chan net.Conn, 1)
			serverErrors := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					serverErrors <- err
					return
				}
				if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
					conn.Close()
					serverErrors <- err
					return
				}
				if _, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"); err != nil {
					conn.Close()
					serverErrors <- err
					return
				}
				accepted <- conn
			}()
			upstream, err := ws.Connect(ws.DialOptions{Host: "127.0.0.1", Domain: "localhost", Port: listener.Addr().(*net.TCPAddr).Port, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer upstream.Close()
			var peer net.Conn
			select {
			case peer = <-accepted:
			case err := <-serverErrors:
				t.Fatal(err)
			case <-time.After(time.Second):
				t.Fatal("upstream handshake timed out")
			}
			defer peer.Close()
			client, local := net.Pipe()
			defer client.Close()
			defer local.Close()
			init, err := crypto.GenerateRelayInit(proto.ProtoTagIntermediate, 2)
			if err != nil {
				t.Fatal(err)
			}
			ciphers, err := crypto.NewCryptoContext(make([]byte, 48), make([]byte, 16), init)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() {
				BridgeWS(ctx, client, upstream, ciphers, nil, &Stats{}, 2, false)
				close(done)
			}()
			if _, err := local.Write([]byte{0}); err != nil {
				t.Fatal(err)
			}
			if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			var frame [7]byte
			if _, err := io.ReadFull(peer, frame[:]); err != nil {
				t.Fatal(err)
			}
			switch trigger {
			case "cancel":
				cancel()
			case "client":
				local.Close()
			case "upstream":
				peer.Close()
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("bridge remained blocked")
			}
			if trigger != "client" {
				if _, err := local.Write([]byte{0}); err == nil {
					t.Fatal("client connection remained open")
				}
			}
			if trigger != "upstream" {
				if _, err := io.Copy(io.Discard, peer); err != nil {
					t.Fatalf("upstream socket not closed: %v", err)
				}
			}
		})
	}
}
