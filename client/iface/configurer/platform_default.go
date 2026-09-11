//go:build !harmony

package configurer

import "runtime"

func supportsLinuxConfigurerOps() bool {
	return runtime.GOOS == "linux"
}
