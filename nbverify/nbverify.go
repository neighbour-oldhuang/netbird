package main

// #include <stdlib.h>
import "C"

import (
	"fmt"
	"sync"
	"net/netip"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.org/x/crypto/curve25519"
	"crypto/rand"
)

// NbSelfTest 触发真实的 netbird/wireguard 依赖 + 多 goroutine + crypto,
// 用来放大 c-archive 里的 runtime 使用量,检验 IE-TLS patch 后的运行稳定性。
// 返回一段描述字符串(调用方 free)。
//
//export NbSelfTest
func NbSelfTest() *C.char {
	var report string

	// 1) crypto: 生成一对 curve25519 密钥(WireGuard 用的曲线)
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return C.CString("rand err: " + err.Error())
	}
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return C.CString("curve25519 err: " + err.Error())
	}
	report += fmt.Sprintf("wg pubkey len=%d; ", len(pub))

	// 2) 多 goroutine + channel + WaitGroup,压 runtime 调度器
	var wg sync.WaitGroup
	results := make(chan int, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			s := 0
			for j := 0; j < n*1000; j++ {
				s += j
			}
			results <- s
		}(i)
	}
	wg.Wait()
	close(results)
	total := 0
	for r := range results {
		total += r
	}
	report += fmt.Sprintf("goroutines sum=%d; ", total)

	// 3) 实例化一个 userspace WireGuard device(netstack TUN,纯用户态,不碰系统 TUN)
	//    这会拉入 wireguard-go 的完整 runtime 使用(goroutine 池、加密握手栈等)
	localIP := netip.MustParseAddr("10.0.0.2")
	dnsIP := netip.MustParseAddr("8.8.8.8")
	tunDev, _, err := netstack.CreateNetTUN([]netip.Addr{localIP}, []netip.Addr{dnsIP}, 1280)
	if err != nil {
		report += "netstack tun err: " + err.Error()
		return C.CString(report)
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "nbtest"))
	if dev != nil {
		report += "wg device created OK; "
		dev.Close()
	}

	report += "NB_SELFTEST_DONE"
	return C.CString(report)
}

func main() {}
