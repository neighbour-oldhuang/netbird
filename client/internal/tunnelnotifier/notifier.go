package tunnelnotifier

import (
	"container/list"
	"sync"

	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/listener"
)

type eventKind int

const (
	eventRoutes eventKind = iota
	eventIfaceIP
	eventIfaceIPv6
	eventDNS
	eventMTU
	eventDNSAddress
)

var (
	_ listener.NetworkChangeListener = (*Notifier)(nil)
	_ dns.MobileDNSManager           = (*Notifier)(nil)
)

type event struct {
	kind       eventKind
	payload    string
	intPayload int
}

type Notifier struct {
	mu     sync.Mutex
	cond   *sync.Cond
	queue  *list.List
	closed bool
	done   chan struct{}

	listener   listener.NetworkChangeListener
	dnsManager dns.MobileDNSManager
}

func New(l listener.NetworkChangeListener, dm dns.MobileDNSManager) *Notifier {
	n := &Notifier{
		queue:      list.New(),
		done:       make(chan struct{}),
		listener:   l,
		dnsManager: dm,
	}
	n.cond = sync.NewCond(&n.mu)
	go n.deliverLoop()
	return n
}

func (n *Notifier) OnNetworkChanged(routes string) {
	n.enqueue(event{kind: eventRoutes, payload: routes})
}

func (n *Notifier) SetInterfaceIP(ip string) {
	n.enqueue(event{kind: eventIfaceIP, payload: ip})
}

func (n *Notifier) SetInterfaceIPv6(ip string) {
	n.enqueue(event{kind: eventIfaceIPv6, payload: ip})
}

func (n *Notifier) ApplyDns(config string) {
	n.enqueue(event{kind: eventDNS, payload: config})
}

func (n *Notifier) SetMTU(mtu int) {
	n.enqueue(event{kind: eventMTU, intPayload: mtu})
}

func (n *Notifier) SetDNSAddress(address string) {
	n.enqueue(event{kind: eventDNSAddress, payload: address})
}

// Close stops accepting new events and blocks until the delivery loop has
// drained all queued events and exited.
func (n *Notifier) Close() {
	n.mu.Lock()
	n.closed = true
	n.cond.Signal()
	n.mu.Unlock()
	<-n.done
}

func (n *Notifier) enqueue(ev event) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return
	}
	n.queue.PushBack(ev)
	n.cond.Signal()
}

func (n *Notifier) deliverLoop() {
	defer close(n.done)
	for {
		n.mu.Lock()
		for n.queue.Len() == 0 && !n.closed {
			n.cond.Wait()
		}
		if n.closed && n.queue.Len() == 0 {
			n.mu.Unlock()
			return
		}
		ev := n.queue.Remove(n.queue.Front()).(event)
		l := n.listener
		dm := n.dnsManager
		n.mu.Unlock()

		switch ev.kind {
		case eventRoutes:
			if l != nil {
				l.OnNetworkChanged(ev.payload)
			}
		case eventIfaceIP:
			if l != nil {
				l.SetInterfaceIP(ev.payload)
			}
		case eventIfaceIPv6:
			if l != nil {
				l.SetInterfaceIPv6(ev.payload)
			}
		case eventDNS:
			if dm != nil {
				dm.ApplyDns(ev.payload)
			}
		case eventMTU:
			if target, ok := l.(interface{ SetMTU(int) }); ok {
				target.SetMTU(ev.intPayload)
			}
		case eventDNSAddress:
			if target, ok := dm.(interface{ SetDNSAddress(string) }); ok {
				target.SetDNSAddress(ev.payload)
			}
		}
	}
}
