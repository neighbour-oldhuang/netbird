//go:build harmony

package grpc

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestHarmonyDialContextUsesStandardDialer(t *testing.T) {
	if !useStandardPlatformDialer {
		t.Fatal("Harmony build did not select the standard platform dialer")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := dialContext(ctx, listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	select {
	case serverConn := <-accepted:
		_ = serverConn.Close()
	case <-ctx.Done():
		t.Fatal("standard dialer connection was not accepted")
	}
}
