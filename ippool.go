package packethose

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

// ipPool allocates /32 IPv4 addresses from a CIDR, skipping the network
// and broadcast addresses plus a configurable reserve (typically the
// server's own tunnel IP).
//
// Single-instance, multi-goroutine safe.
type ipPool struct {
	subnet   netip.Prefix
	reserved map[netip.Addr]bool

	mu        sync.Mutex
	used      map[netip.Addr]bool
	byClient  map[[clientIDLen]byte]netip.Addr // sticky: returning client gets same IP
}

func newIPPool(subnet netip.Prefix, reserved ...netip.Addr) (*ipPool, error) {
	if !subnet.IsValid() || !subnet.Addr().Is4() {
		return nil, errors.New("ipPool: subnet must be a valid IPv4 prefix")
	}
	if subnet.Bits() > 30 {
		return nil, fmt.Errorf("ipPool: subnet /%d too small (need at least /30)", subnet.Bits())
	}
	p := &ipPool{
		subnet:   subnet.Masked(),
		reserved: make(map[netip.Addr]bool),
		used:     make(map[netip.Addr]bool),
		byClient: make(map[[clientIDLen]byte]netip.Addr),
	}
	// Reserve the network and broadcast addresses.
	p.reserved[p.subnet.Addr()] = true
	p.reserved[broadcast(p.subnet)] = true
	for _, r := range reserved {
		if r.IsValid() {
			p.reserved[r] = true
		}
	}
	return p, nil
}

// Allocate returns (newly-allocated or sticky) IP for clientID. If preferred
// is in-pool and free, it is honored; otherwise next free.
func (p *ipPool) Allocate(clientID [clientIDLen]byte, preferred netip.Addr) (netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if cur, ok := p.byClient[clientID]; ok {
		return cur, nil
	}

	if preferred.IsValid() && !preferred.IsUnspecified() && p.subnet.Contains(preferred) &&
		!p.reserved[preferred] && !p.used[preferred] {
		p.used[preferred] = true
		p.byClient[clientID] = preferred
		return preferred, nil
	}

	for addr := nextAddr(p.subnet.Addr()); p.subnet.Contains(addr); addr = nextAddr(addr) {
		if p.reserved[addr] || p.used[addr] {
			continue
		}
		p.used[addr] = true
		p.byClient[clientID] = addr
		return addr, nil
	}
	return netip.Addr{}, errors.New("ipPool: exhausted")
}

// Release returns an IP to the pool. Idempotent.
func (p *ipPool) Release(clientID [clientIDLen]byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if addr, ok := p.byClient[clientID]; ok {
		delete(p.used, addr)
		delete(p.byClient, clientID)
	}
}

func nextAddr(a netip.Addr) netip.Addr {
	b := a.As4()
	for i := 3; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			break
		}
	}
	return netip.AddrFrom4(b)
}

func broadcast(p netip.Prefix) netip.Addr {
	a := p.Addr().As4()
	mask := uint32(0xFFFFFFFF) >> uint(p.Bits())
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v |= mask
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
