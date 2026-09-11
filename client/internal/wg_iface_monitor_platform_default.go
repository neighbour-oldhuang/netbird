//go:build !harmony

package internal

func wgIfaceMonitorSupported() bool {
	return true
}
