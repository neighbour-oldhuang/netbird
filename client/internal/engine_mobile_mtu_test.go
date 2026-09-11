package internal

import "testing"

type platformMTURecorder struct {
	mtu int
}

func (r *platformMTURecorder) SetMTU(mtu int) {
	r.mtu = mtu
}

func TestNotifyPlatformMTU(t *testing.T) {
	recorder := &platformMTURecorder{}
	if !notifyPlatformMTU(recorder, 1280) {
		t.Fatal("MTU-capable listener was not detected")
	}
	if recorder.mtu != 1280 {
		t.Fatalf("MTU callback received %d, want 1280", recorder.mtu)
	}
	if notifyPlatformMTU(struct{}{}, 1280) {
		t.Fatal("listener without SetMTU was reported as MTU-capable")
	}
}

type platformDNSRecorder struct {
	address string
}

func (r *platformDNSRecorder) SetDNSAddress(address string) {
	r.address = address
}

func TestNotifyPlatformDNSAddress(t *testing.T) {
	recorder := &platformDNSRecorder{}
	if !notifyPlatformDNSAddress(recorder, "100.64.0.53") {
		t.Fatal("DNS-capable listener was not detected")
	}
	if recorder.address != "100.64.0.53" {
		t.Fatalf("DNS callback received %q", recorder.address)
	}
	if notifyPlatformDNSAddress(struct{}{}, "100.64.0.53") || notifyPlatformDNSAddress(recorder, " ") {
		t.Fatal("invalid DNS callback target or address was accepted")
	}
}
