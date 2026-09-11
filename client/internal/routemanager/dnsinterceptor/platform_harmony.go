//go:build harmony

package dnsinterceptor

// HarmonyOS builds with GOOS=linux, so the platform cannot be detected at runtime.
func isHarmonyBuild() bool {
	return true
}
