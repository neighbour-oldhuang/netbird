//go:build harmony

package notifier

import (
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/route"
)

type Notifier struct {
	mu              sync.Mutex
	currentPrefixes []string
	listener        listener.NetworkChangeListener
}

func NewNotifier() *Notifier { return &Notifier{} }

func (n *Notifier) SetListener(l listener.NetworkChangeListener) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.listener = l
}

func (n *Notifier) NotifyRouteChange()      {}
func (n *Notifier) OnNewRoutes(route.HAMap) {}

func (n *Notifier) OnNewPrefixes(prefixes []netip.Prefix) {
	newNets := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		newNets = append(newNets, prefix.String())
	}
	sort.Strings(newNets)

	n.mu.Lock()
	defer n.mu.Unlock()
	if slices.Equal(n.currentPrefixes, newNets) {
		return
	}
	n.currentPrefixes = newNets
	if n.listener != nil {
		n.listener.OnNetworkChanged(strings.Join(newNets, ","))
	}
}

func (n *Notifier) Close()                          {}
func (n *Notifier) GetInitialRouteRanges() []string { return nil }
