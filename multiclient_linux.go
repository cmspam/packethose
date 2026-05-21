//go:build linux

package packethose

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os/exec"
	"sync"
	"time"
)

// multiClientLoop accepts inbound connections, groups them by client ID, and
// runs each session against a per-client kernel TUN device.
//
// Pre-conditions on the server's Linux host:
//   - CAP_NET_ADMIN to create TUN devices and configure addresses
//   - net.ipv4.ip_forward=1 if clients should reach the wider internet
//   - iptables MASQUERADE on the egress interface for the Subnet (or
//     equivalent nftables rule)
//
// Per-client lifecycle:
//   1. First lane arrives → handshake → pool.Allocate → create TUN with
//      laneCount queues → configure /<prefix> + assigned addr → add lane.
//   2. Subsequent lanes match the existing session by client ID and consume
//      the next free queue.
//   3. When all lanes are idle for sessionIdle, the session is torn down
//      (TUN deleted, pool slot released, sticky map updated so the same
//      client gets the same IP if it reconnects later).
func multiClientLoop(ctx context.Context, ln net.Listener, cfg ServerConfig, pool *ipPool, logger *log.Logger) error {
	state := &mcState{
		cfg:      cfg,
		pool:     pool,
		logger:   logger,
		sessions: map[[clientIDLen]byte]*session{},
	}
	// Server-side tunnel IP lives on loopback so it is reachable from every
	// per-client TUN (a packet arriving on phose-XYZ with dst=ServerIP gets
	// delivered to the local stack via the lo /32 route).
	serverCIDR := fmt.Sprintf("%s/32", cfg.ServerIP.String())
	if err := exec.Command("ip", "addr", "replace", serverCIDR, "dev", "lo").Run(); err != nil {
		logger.Printf("warn: failed to add %s to lo: %v (server tunnel IP may be unreachable)", serverCIDR, err)
	} else {
		logger.Printf("server tunnel IP %s installed on lo", serverCIDR)
	}
	go state.gc(ctx)

	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			logger.Printf("accept: %v", err)
			if !sleepJitter(ctx, 500*time.Millisecond) {
				return ctx.Err()
			}
			continue
		}
		if cfg.AllowIP != "" {
			if ip := remoteIP(c); ip != cfg.AllowIP {
				logger.Printf("reject %s (allow=%s)", ip, cfg.AllowIP)
				c.Close()
				continue
			}
		}
		go state.handleConn(ctx, c)
	}
}

type mcState struct {
	cfg    ServerConfig
	pool   *ipPool
	logger *log.Logger

	mu       sync.Mutex
	sessions map[[clientIDLen]byte]*session
}

type session struct {
	id         [clientIDLen]byte
	assignedIP netip.Addr
	peerIP     netip.Addr
	prefixLen  byte
	tunName    string
	queues     []PacketIO
	laneCount  int

	mu       sync.Mutex
	nextLane int
	active   int
	lastSeen time.Time
	closed   bool

	ctx    context.Context
	cancel context.CancelFunc
}

func (m *mcState) handleConn(ctx context.Context, c net.Conn) {
	assignFn := func(clientID [clientIDLen]byte, requested netip.Addr) (netip.Addr, netip.Addr, byte) {
		addr, err := m.pool.Allocate(clientID, requested)
		if err != nil {
			m.logger.Printf("ipPool: %v", err)
			return zeroAddrV4(), zeroAddrV4(), 0
		}
		return addr, m.cfg.ServerIP, byte(m.cfg.Subnet.Bits())
	}
	ident, err := acceptHandshake(c, m.cfg.PSK, assignFn)
	if err != nil {
		m.logger.Printf("handshake fail from %s: %v", c.RemoteAddr(), err)
		c.Close()
		return
	}
	if !ident.assignedIP.IsValid() || ident.prefixLen == 0 {
		m.logger.Printf("multi-client requires PSK + IP assignment; rejecting %s", c.RemoteAddr())
		c.Close()
		return
	}

	sess, isNew, err := m.acquireSession(ctx, ident)
	if err != nil {
		m.logger.Printf("session %s: %v", c.RemoteAddr(), err)
		c.Close()
		return
	}
	if isNew {
		m.logger.Printf("session %x: assigned %s/%d (tun %s, lanes=%d)",
			ident.clientID[:4], ident.assignedIP, ident.prefixLen, sess.tunName, sess.laneCount)
	}

	sess.mu.Lock()
	queueIdx := sess.nextLane
	sess.nextLane = (sess.nextLane + 1) % sess.laneCount
	sess.active++
	sess.lastSeen = time.Now()
	pio := sess.queues[queueIdx]
	sess.mu.Unlock()

	defer func() {
		sess.mu.Lock()
		sess.active--
		sess.lastSeen = time.Now()
		sess.mu.Unlock()
	}()

	ioDone := make(chan struct{})
	go func() {
		select {
		case <-sess.ctx.Done():
			c.Close()
		case <-ioDone:
		}
	}()
	runLane(pio, c, ident.keys, m.cfg.TuneSocket, m.logger)
	close(ioDone)
}

func (m *mcState) acquireSession(parent context.Context, ident laneIdentity) (*session, bool, error) {
	m.mu.Lock()
	if s, ok := m.sessions[ident.clientID]; ok {
		m.mu.Unlock()
		return s, false, nil
	}
	// Build the session under m.mu held so concurrent first lanes from
	// the same client cooperate on a single TUN creation.
	laneCount := int(ident.laneCount)
	if laneCount < 1 {
		laneCount = 1
	}
	if laneCount > 64 {
		laneCount = 64
	}
	tunName := tunDeviceName(m.cfg.TUNPrefix, ident.clientID)
	queues, ifname, err := OpenKernelTUN(tunName, laneCount, m.cfg.VnetHdr)
	if err != nil {
		m.mu.Unlock()
		m.pool.Release(ident.clientID)
		return nil, false, fmt.Errorf("open tun %s: %w", tunName, err)
	}
	if err := configureSessionInterface(ifname, ident.assignedIP); err != nil {
		closeAll(queues)
		m.mu.Unlock()
		m.pool.Release(ident.clientID)
		return nil, false, fmt.Errorf("configure %s: %w", ifname, err)
	}
	ctx, cancel := context.WithCancel(parent)
	s := &session{
		id:         ident.clientID,
		assignedIP: ident.assignedIP,
		peerIP:     ident.peerIP,
		prefixLen:  ident.prefixLen,
		tunName:    ifname,
		queues:     queues,
		laneCount:  laneCount,
		lastSeen:   time.Now(),
		ctx:        ctx,
		cancel:     cancel,
	}
	m.sessions[ident.clientID] = s
	m.mu.Unlock()
	return s, true, nil
}

func (m *mcState) gc(ctx context.Context) {
	const idle = 90 * time.Second
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			m.tearDownAll()
			return
		case <-tick.C:
			m.collect(idle)
		}
	}
}

func (m *mcState) collect(idle time.Duration) {
	now := time.Now()
	m.mu.Lock()
	var victims []*session
	for id, s := range m.sessions {
		s.mu.Lock()
		stale := s.active == 0 && now.Sub(s.lastSeen) > idle
		s.mu.Unlock()
		if stale {
			delete(m.sessions, id)
			victims = append(victims, s)
		}
	}
	m.mu.Unlock()
	for _, s := range victims {
		m.tearDown(s)
	}
}

func (m *mcState) tearDownAll() {
	m.mu.Lock()
	victims := make([]*session, 0, len(m.sessions))
	for _, s := range m.sessions {
		victims = append(victims, s)
	}
	m.sessions = map[[clientIDLen]byte]*session{}
	m.mu.Unlock()
	for _, s := range victims {
		m.tearDown(s)
	}
}

func (m *mcState) tearDown(s *session) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	s.cancel()
	closeAll(s.queues)
	_ = exec.Command("ip", "link", "del", s.tunName).Run()
	m.pool.Release(s.id)
	m.logger.Printf("session %x: torn down (tun %s)", s.id[:4], s.tunName)
}

func closeAll(qs []PacketIO) {
	for _, q := range qs {
		_ = q.Close()
	}
}

func tunDeviceName(prefix string, id [clientIDLen]byte) string {
	if prefix == "" {
		prefix = "phose"
	}
	short := hex.EncodeToString(id[:3])
	name := prefix + "-" + short
	// Linux IFNAMSIZ is 16 (incl. NUL) → 15 usable chars.
	if len(name) > 15 {
		name = name[:15]
	}
	return name
}

func configureSessionInterface(name string, clientAddr netip.Addr) error {
	if err := exec.Command("ip", "link", "set", name, "up").Run(); err != nil {
		return fmt.Errorf("ip link set up: %w", err)
	}
	// Install a /32 host route to the client's tunnel IP via this device.
	// We do NOT assign an address from the subnet to the TUN itself; the
	// server's tunnel IP lives on lo (so it can serve every client without
	// per-interface conflicts), and the kernel routes inbound replies to
	// the client via this /32.
	route := fmt.Sprintf("%s/32", clientAddr.String())
	if err := exec.Command("ip", "route", "replace", route, "dev", name).Run(); err != nil {
		return fmt.Errorf("ip route replace: %w", err)
	}
	return nil
}

