package client

import (
	"context"
	"testing"
)

func TestContextWithDialAddress(t *testing.T) {
	base := context.Background()
	if got := dialAddressFromContext(base); got != "" {
		t.Fatalf("base context dial address = %q", got)
	}
	withAddress := ContextWithDialAddress(base, "127.0.0.1:18443")
	if got := dialAddressFromContext(withAddress); got != "127.0.0.1:18443" {
		t.Fatalf("dial address = %q", got)
	}
	if got := dialAddressFromContext(base); got != "" {
		t.Fatalf("base context was mutated: %q", got)
	}
}
