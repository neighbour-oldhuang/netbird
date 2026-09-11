//go:build harmony

package debug

func (g *BundleGenerator) addPlatformLog() error {
	if g.logPath == "" {
		return nil
	}
	return g.addLogfile()
}
