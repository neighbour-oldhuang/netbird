//go:build harmony

package routemanager

// HarmonyOS builds with GOOS=linux, so the platform cannot be detected at runtime.
func isHarmonyBuild() bool {
	return true
}
