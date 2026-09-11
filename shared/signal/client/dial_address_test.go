package client

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
)

func TestContextWithDialAddress(t *testing.T) {
	base := context.Background()
	if got := dialAddressFromContext(base); got != "" {
		t.Fatalf("base context dial address = %q", got)
	}
	withAddress := ContextWithDialAddress(base, "127.0.0.1:18447")
	if got := dialAddressFromContext(withAddress); got != "127.0.0.1:18447" {
		t.Fatalf("dial address = %q", got)
	}
	if got := dialAddressFromContext(base); got != "" {
		t.Fatalf("base context was mutated: %q", got)
	}
}

func TestContextDialAddressPreservesSignalTarget(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Stop()

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = ContextWithDialAddress(ctx, listener.Addr().String())

	const configuredTarget = "signal.example.invalid:443"
	client, err := NewClient(ctx, configuredTarget, key, false)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if got := client.signalConn.Target(); got != configuredTarget {
		t.Fatalf("signal target = %q, want %q", got, configuredTarget)
	}
}
