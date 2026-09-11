//go:build harmony

package iface

// Destroy is intentionally a no-op on HarmonyOS. The platform
// VpnConnection owns interface destruction; Go owns only a duplicated fd.
func (w *WGIface) Destroy() error {
	return nil
}
