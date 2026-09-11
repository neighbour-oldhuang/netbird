//go:build !harmony

package main

import "fmt"

func runFDTunSelfTest() (string, error) {
	return "", fmt.Errorf("fd TUN self-test requires the harmony build tag")
}
