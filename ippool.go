package packethose

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

// ipPool allocates host addresses from a CIDR for connecting clients.
//
// IPv4: bitmap-style sticky allocation, skipping the network and broadcast
// addresses plus any reserved entries (typically the server's own tunnel IP).
//
// IPv6: hash-derived allocation. We pick host bits by hashing the client_id,
// XORing into the subnet's network portion. With /64 or larger the collision
// probability is negligible across realistic client counts. A sticky map
// still records the chosen address so reconnecting clients keep their
// address even across server restarts (within the same process lifetime).
//
// Single-instance, multi-goroutine safe.
type ipPool struct {
	subnet   netip.Prefix
	reserved map[netip.Addr]bool
	isV4     bool

	mu       sync.Mutex
	used     map[netip.Addr]bool                 // bitmap occupancy (v4)
	byClient map[[clientIDLen]byte]netip.Addr    // sticky map
}

func newIPPool(subnet netip.Prefix, reserved ...netip.Addr) (*ipPool, error) {
	if !subnet.IsValid() {
		return nil, errors.New("ipPool: invalid subnet")
	}
	subnet = subnet.Masked()
	isV4 := subnet.Addr().Is4()
	if isV4 && subnet.Bits() > 30 {
		return nil, fmt.Errorf("ipPool: v4 subnet /%d too small (need >= /30)", subnet.Bits())
	}
	if !isV4 && subnet.Bits() > 126 {
		return nil, fmt.Errorf("ipPool: v6 subnet /%d too small (need >= /126)", subnet.Bits())
	}
	p := &ipPool{
		subnet:   subnet,
		reserved: make(map[netip.Addr]bool),
		isV4:     isV4,
		used:     make(map[netip.Addr]bool),
		byClient: make(map[[clientIDLen]byte]netip.Addr),
	}
	p.reserved[subnet.Addr()] = true
	if isV4 {
		p.reserved[broadcast4(subnet)] = true
	}
	for _, r := range reserved {
		if r.IsValid() {
			p.reserved[r] = true
		}
	}
	return p, nil
}

// Allocate returns (newly-allocated or sticky) host address for clientID.
// If preferred is non-zero, in-subnet, and free, it is honored.
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

	if p.isV4 {
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

	// IPv6: hash-derived. Try a few hash rotations on collision.
	for round := byte(0); round < 8; round++ {
		candidate := v6FromClientID(p.subnet, clientID, round)
		if p.reserved[candidate] || p.used[candidate] {
			continue
		}
		p.used[candidate] = true
		p.byClient[clientID] = candidate
		return candidate, nil
	}
	return netip.Addr{}, errors.New("ipPool: v6 hash collision (try a larger subnet)")
}

// Release returns a client's IP to the pool. Idempotent.
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

func broadcast4(p netip.Prefix) netip.Addr {
	a := p.Addr().As4()
	mask := uint32(0xFFFFFFFF) >> uint(p.Bits())
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v |= mask
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// v6FromClientID derives an in-subnet IPv6 address from the client_id. The
// network bits come from the subnet; the host bits come from SHA-256 of
// (round || client_id), masked to the host-bits region.
func v6FromClientID(subnet netip.Prefix, clientID [clientIDLen]byte, round byte) netip.Addr {
	h := sha256.New()
	h.Write([]byte{round})
	h.Write(clientID[:])
	digest := h.Sum(nil)

	netBytes := subnet.Addr().As16()
	bits := subnet.Bits()
	// Compute host mask: 1s in the host-bits region.
	out := netBytes
	fullHostBytes := (128 - bits) / 8
	remainderBits := (128 - bits) % 8
	for i := 0; i < fullHostBytes; i++ {
		out[15-i] = digest[i]
	}
	if remainderBits > 0 {
		boundary := 15 - fullHostBytes
		hostMask := byte(0xFF) >> (8 - remainderBits) // low remainderBits bits
		out[boundary] = (netBytes[boundary] &^ hostMask) | (digest[fullHostBytes] & hostMask)
	}

	addr := netip.AddrFrom16(out)
	// Never return the all-zero host portion (== subnet network address).
	if addr == subnet.Addr() {
		// Force the last byte to a non-zero deterministic value.
		_ = binary.BigEndian.Uint64(digest[:8])
		out[15] |= 0x01
		addr = netip.AddrFrom16(out)
	}
	return addr
}
