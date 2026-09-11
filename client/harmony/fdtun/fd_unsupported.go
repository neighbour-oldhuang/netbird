//go:build !harmony

package fdtun

import "fmt"

func NewFromFD(fd int, name string, mtu int) (*Device, error) {
	return nil, fmt.Errorf("%w: fd=%d", ErrUnsupported, fd)
}
