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
// Per-client lifecycle:
//   1. First lane arrives -> handshake -> per-family pool allocation
//      (v4 from Subnet, v6 from Subnet6, either or both) -> create TUN with
//      laneCount queues -> install host routes for the assigned address(es)
//      -> add lane.
//   2. Subsequent lanes from the same client match the existing session and
//      consume the next queue.
//   3. After all lanes are idle for sessionIdle, the session is collected:
//      the TUN is deleted, pool slots released, sticky maps keep the
//      address(es) so the same client gets the same allocation on
//      reconnect.
func multiClientLoop(ctx context.Context, ln net.Listener, cfg ServerConfig, pool4, pool6 *ipPool, logger *log.Logger) error {
	state := &mcState{
		cfg:      cfg,
		pool4:    pool4,
		pool6:    pool6,
		logger:   logger,
		sessions: map[[clientIDLen]byte]*session{},
	}
	// Server-side tunnel IPs live on loopback so each per-client TUN can
	// reach them without /24-or-/64 conflicts between sessions.
	if pool4 != nil {
		cidr := fmt.Sprintf("%s/32", cfg.ServerIP.String())
		if err := exec.Command("ip", "addr", "replace", cidr, "dev", "lo").Run(); err != nil {
			logger.Printf("warn: install %s on lo: %v", cidr, err)
		} else {
			logger.Printf("server tunnel v4 IP %s installed on lo", cidr)
		}
	}
	if pool6 != nil {
		cidr := fmt.Sprintf("%s/128", cfg.ServerIP6.String())
		if err := exec.Command("ip", "-6", "addr", "replace", cidr, "dev", "lo").Run(); err != nil {
			logger.Printf("warn: install %s on lo: %v", cidr, err)
		} else {
			logger.Printf("server tunnel v6 IP %s installed on lo", cidr)
		}
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
	cfg          ServerConfig
	pool4, pool6 *ipPool
	logger       *log.Logger

	mu       sync.Mutex
	sessions map[[clientIDLen]byte]*session
}

type session struct {
	id        [clientIDLen]byte
	assigned4 netip.Addr
	assigned6 netip.Addr
	tunName   string
	queues    []PacketIO
	laneCount int

	mu       sync.Mutex
	nextLane int
	active   int
	lastSeen time.Time
	closed   bool

	ctx    context.Context
	cancel context.CancelFunc
}

func (m *mcState) handleConn(ctx context.Context, c net.Conn) {
	assignFn := func(clientID [clientIDLen]byte, req AssignmentRequest) AssignmentResponse {
		var resp AssignmentResponse
		if m.pool4 != nil {
			addr, err := m.pool4.Allocate(clientID, req.V4)
			if err != nil {
				m.logger.Printf("ipPool v4: %v", err)
			} else {
				resp.V4Addr = addr
				resp.V4Prefix = byte(m.cfg.Subnet.Bits())
				resp.V4Peer = m.cfg.ServerIP
			}
		}
		if m.pool6 != nil {
			addr, err := m.pool6.Allocate(clientID, req.V6)
			if err != nil {
				m.logger.Printf("ipPool v6: %v", err)
			} else {
				resp.V6Addr = addr
				resp.V6Prefix = byte(m.cfg.Subnet6.Bits())
				resp.V6Peer = m.cfg.ServerIP6
			}
		}
		return resp
	}
	ident, err := acceptHandshake(c, m.cfg.PSK, assignFn)
	if err != nil {
		m.logger.Printf("handshake fail from %s: %v", c.RemoteAddr(), err)
		c.Close()
		return
	}
	if !ident.hasAssignment() {
		m.logger.Printf("multi-client server allocated no address for client; rejecting %s", c.RemoteAddr())
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
		var addrs []string
		if ident.assigned4.IsValid() {
			addrs = append(addrs, fmt.Sprintf("%s/%d", ident.assigned4, ident.prefix4))
		}
		if ident.assigned6.IsValid() {
			addrs = append(addrs, fmt.Sprintf("%s/%d", ident.assigned6, ident.prefix6))
		}
		m.logger.Printf("session %x: assigned %v on %s (lanes=%d)",
			ident.clientID[:4], addrs, sess.tunName, sess.laneCount)
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
		m.releaseAll(ident.clientID)
		return nil, false, fmt.Errorf("open tun %s: %w", tunName, err)
	}
	if err := configureSessionInterface(ifname, ident.assigned4, ident.assigned6); err != nil {
		closeAll(queues)
		m.mu.Unlock()
		m.releaseAll(ident.clientID)
		return nil, false, fmt.Errorf("configure %s: %w", ifname, err)
	}
	ctx, cancel := context.WithCancel(parent)
	s := &session{
		id:        ident.clientID,
		assigned4: ident.assigned4,
		assigned6: ident.assigned6,
		tunName:   ifname,
		queues:    queues,
		laneCount: laneCount,
		lastSeen:  time.Now(),
		ctx:       ctx,
		cancel:    cancel,
	}
	m.sessions[ident.clientID] = s
	m.mu.Unlock()
	return s, true, nil
}

func (m *mcState) releaseAll(id [clientIDLen]byte) {
	if m.pool4 != nil {
		m.pool4.Release(id)
	}
	if m.pool6 != nil {
		m.pool6.Release(id)
	}
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
	m.releaseAll(s.id)
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
	if len(name) > 15 {
		name = name[:15]
	}
	return name
}

func configureSessionInterface(name string, addrV4, addrV6 netip.Addr) error {
	if err := exec.Command("ip", "link", "set", name, "up").Run(); err != nil {
		return fmt.Errorf("ip link set up: %w", err)
	}
	if addrV4.IsValid() {
		route := fmt.Sprintf("%s/32", addrV4.String())
		if err := exec.Command("ip", "route", "replace", route, "dev", name).Run(); err != nil {
			return fmt.Errorf("ip route replace v4: %w", err)
		}
	}
	if addrV6.IsValid() {
		route := fmt.Sprintf("%s/128", addrV6.String())
		if err := exec.Command("ip", "-6", "route", "replace", route, "dev", name).Run(); err != nil {
			return fmt.Errorf("ip route replace v6: %w", err)
		}
	}
	return nil
}
