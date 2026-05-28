//go:build linux

package packethose

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/flynn/noise"
)

// multiClientLoop accepts inbound connections, groups them by client
// ID, and runs each session against the server's single shared TUN
// device.
//
// Architecture (v0.5+):
//
//   - One shared TUN (default name `phose0`, multi-queue). The pool
//     /N and /M live directly on this device, so the kernel sees all
//     clients as directly connected. No per-client TUN, no per-client
//     route in main.
//
//   - N reader goroutines (one per multi-queue fd) pull inbound
//     packets the kernel wrote to the shared device (destination is
//     a client tunnel IP), parse the inner L3 destination, look up
//     the owning session in mcState.ipIndex, and push to the
//     session's bounded outbound channel.
//
//   - Each accepted outer TCP lane gets a sessionPIO wrapper whose
//     Read pulls from the session's outbound channel and whose Write
//     goes to one of the shared TUN's queues (round-robin per lane
//     index). lane.go is unchanged.
//
//   - Per-client backpressure lives in the bounded outbound channel:
//     a noisy client's queue fills and the tunReaders drop packets
//     for that client only; other clients keep flowing.
func multiClientLoop(ctx context.Context, ln net.Listener, cfg ServerConfig, userDB *userDBHolder, static noise.DHKey, pool4, pool6 *ipPool, metrics *Metrics, logger *log.Logger) error {
	tunName := cfg.TUNName
	if tunName == "" {
		tunName = "phose0"
	}
	queueCount := cfg.SharedTUNQueues
	if queueCount <= 0 {
		queueCount = runtime.NumCPU()
	}
	queues, ifname, err := OpenKernelTUN(tunName, queueCount, cfg.VnetHdr)
	if err != nil {
		return fmt.Errorf("open shared tun %s: %w", tunName, err)
	}
	defer closeAll(queues)
	defer exec.Command("ip", "link", "del", ifname).Run()

	if err := configureSharedInterface(ifname, cfg); err != nil {
		return fmt.Errorf("configure shared tun %s: %w", ifname, err)
	}
	logger.Printf("shared tun %s opened with %d queues (vnet_hdr=%v)", ifname, len(queues), cfg.VnetHdr)

	state := &mcState{
		cfg:           cfg,
		userDB:        userDB,
		static:        static,
		pool4:         pool4,
		pool6:         pool6,
		logger:        logger,
		metrics:       metrics,
		limiter:       newConnLimiter(cfg.RateLimit),
		sharedQueues:  queues,
		sharedIfname:  ifname,
		sharedVnetHdr: cfg.VnetHdr,
		sessions:      map[[clientIDLen]byte]*session{},
		ipIndex:       map[netip.Addr]*session{},
	}
	for i := range queues {
		go state.runTunReader(ctx, queues[i])
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
		metrics.incAccept()
		ip := remoteIP(c)
		if cfg.AllowIP != "" && ip != cfg.AllowIP {
			logger.Printf("reject %s (allow=%s)", ip, cfg.AllowIP)
			c.Close()
			continue
		}
		if !state.limiter.allowIP(ip) {
			metrics.incRateLimited()
			logger.Printf("rate-limited %s", ip)
			c.Close()
			continue
		}
		release, ok := state.limiter.acquireSlot()
		if !ok {
			metrics.incSlotsFull()
			logger.Printf("handshake slots full; dropping %s", ip)
			c.Close()
			continue
		}
		go state.handleConn(ctx, c, release)
	}
}

type mcState struct {
	cfg          ServerConfig
	userDB       *userDBHolder
	static       noise.DHKey
	pool4, pool6 *ipPool
	logger       *log.Logger
	metrics      *Metrics
	limiter      *connLimiter

	sharedQueues  []PacketIO
	sharedIfname  string
	sharedVnetHdr bool

	mu       sync.Mutex
	sessions map[[clientIDLen]byte]*session
	ipIndex  map[netip.Addr]*session
}

type session struct {
	id        [clientIDLen]byte
	userName  string
	assigned4 netip.Addr
	assigned6 netip.Addr
	laneCount int

	// outbound carries inbound-from-internet packets the shared TUN
	// readers dispatched to this client. Lanes' sessionPIO.Read pulls
	// from this channel; tunReaders push on session match (non-block,
	// dropping when full so a noisy client cannot stall others).
	outbound  chan []byte
	closed    chan struct{}
	closeOnce sync.Once

	mu       sync.Mutex
	nextLane int
	active   int
	lastSeen time.Time
	isClosed bool

	ctx    context.Context
	cancel context.CancelFunc
}

func (m *mcState) handleConn(ctx context.Context, c net.Conn, releaseSlot func()) {
	// The in-flight permit covers the handshake only; it is freed as
	// soon as the handshake resolves so a long-lived session does not
	// hold a slot. The deferred call is the backstop for early returns.
	defer releaseSlot()
	assignFn := func(userName string, clientID [clientIDLen]byte, req AssignmentRequest) (AssignmentResponse, error) {
		// Quota is enforced in acquireSession (per-session, not
		// per-handshake). assignFn just allocates the address.
		var resp AssignmentResponse
		db := m.userDB.get()
		if m.pool4 != nil {
			addr, err := m.pool4.AllocateFor(userName, clientID, req.V4, db)
			if err != nil {
				m.logger.Printf("ipPool v4 user=%q: %v", userName, err)
			} else {
				resp.V4Addr = addr
				resp.V4Prefix = byte(m.cfg.Subnet.Bits())
				resp.V4Peer = m.cfg.ServerIP
			}
		}
		if m.pool6 != nil {
			addr, err := m.pool6.AllocateFor(userName, clientID, req.V6, db)
			if err != nil {
				m.logger.Printf("ipPool v6 user=%q: %v", userName, err)
			} else {
				resp.V6Addr = addr
				resp.V6Prefix = byte(m.cfg.Subnet6.Bits())
				resp.V6Peer = m.cfg.ServerIP6
			}
		}
		return resp, nil
	}
	authorize := serverAuthorizer(m.userDB.get(), m.cfg.PeerPublicKey)
	// USO is negotiated off in multi-client mode: the shared TUN serves all
	// clients, so per-client offload toggling is not possible.
	ident, err := acceptHandshake(c, m.static, m.cfg.Cipher, false, authorize, assignFn)
	if err != nil {
		m.metrics.incHandshakeFail()
		m.logger.Printf("handshake fail from %s: %v", c.RemoteAddr(), err)
		// The handshake authenticates the client before assignFn runs,
		// so an unauthenticated peer never reaches an allocation. A
		// failure after that point (e.g. a dropped write) may have left
		// a speculative allocation; release it when no live session owns
		// this client, so an aborted handshake cannot leak pool entries.
		if ident.clientID != ([clientIDLen]byte{}) {
			m.releaseOrphan(ident.clientID)
		}
		c.Close()
		return
	}
	if !ident.hasAssignment() {
		m.logger.Printf("multi-client server allocated no address for client; rejecting %s", c.RemoteAddr())
		c.Close()
		return
	}

	m.metrics.incHandshakeOK()
	// Handshake done: free the in-flight permit before the session's
	// long-lived I/O loop so the cap counts handshakes, not sessions.
	releaseSlot()

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
		m.logger.Printf("session %x: assigned %v (lanes=%d)", ident.clientID[:4], addrs, sess.laneCount)
	}

	// Pick a shared-TUN queue for this lane's write side. Multiple
	// lanes for the same session share the outbound channel for
	// reads, but each writes to its own assigned queue so the kernel
	// can process them in parallel.
	sess.mu.Lock()
	queueIdx := sess.nextLane % len(m.sharedQueues)
	sess.nextLane++
	sess.active++
	sess.lastSeen = time.Now()
	sess.mu.Unlock()

	defer func() {
		sess.mu.Lock()
		sess.active--
		sess.lastSeen = time.Now()
		sess.mu.Unlock()
	}()

	pio := newSessionPIO(sess, m.sharedQueues[queueIdx], m.sharedVnetHdr)
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
	if db := m.userDB.get(); db != nil && !db.Empty() {
		if err := db.AcquireSlot(ident.userName); err != nil {
			m.mu.Unlock()
			m.releaseAll(ident.clientID)
			return nil, false, err
		}
	}
	laneCount := int(ident.laneCount)
	if laneCount < 1 {
		laneCount = 1
	}
	if laneCount > 64 {
		laneCount = 64
	}
	ctx, cancel := context.WithCancel(parent)
	s := &session{
		id:        ident.clientID,
		userName:  ident.userName,
		assigned4: ident.assigned4,
		assigned6: ident.assigned6,
		laneCount: laneCount,
		outbound:  make(chan []byte, 256),
		closed:    make(chan struct{}),
		lastSeen:  time.Now(),
		ctx:       ctx,
		cancel:    cancel,
	}
	m.sessions[ident.clientID] = s
	if ident.assigned4.IsValid() {
		m.ipIndex[ident.assigned4] = s
		if m.pool4 != nil {
			m.pool4.Claim(ident.clientID, ident.assigned4)
		}
	}
	if ident.assigned6.IsValid() {
		m.ipIndex[ident.assigned6] = s
		if m.pool6 != nil {
			m.pool6.Claim(ident.clientID, ident.assigned6)
		}
	}
	m.mu.Unlock()
	m.metrics.incSessionOpened()
	return s, true, nil
}

// runTunReader reads packets the kernel wrote to the shared TUN
// queue and dispatches each to the session whose tunnel IP matches
// the inner L3 destination. One goroutine per shared-TUN queue.
func (m *mcState) runTunReader(ctx context.Context, q PacketIO) {
	buf := make([]byte, 65535+virtioNetHdrLen)
	for {
		n, err := q.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// Device closed (server shutting down) or transient EAGAIN.
			// Either way the read returns; bail.
			return
		}
		if n <= 0 {
			continue
		}
		dst, ok := innerDst(buf[:n], m.sharedVnetHdr)
		if !ok {
			continue
		}
		m.mu.Lock()
		sess := m.ipIndex[dst]
		m.mu.Unlock()
		if sess == nil {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		select {
		case sess.outbound <- pkt:
		case <-sess.closed:
		default:
			// Session's outbound is full. Drop just this client's
			// packet; other clients are unaffected.
		}
	}
}

func (m *mcState) releaseAll(id [clientIDLen]byte) {
	if m.pool4 != nil {
		m.pool4.Release(id)
	}
	if m.pool6 != nil {
		m.pool6.Release(id)
	}
}

// releaseOrphan frees a client's pool allocation only when no live
// session owns it. It holds m.mu across the release so it cannot race a
// concurrent acquireSession (which claims the same addresses under the
// same lock) for the same client.
func (m *mcState) releaseOrphan(id [clientIDLen]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, live := m.sessions[id]; live {
		return
	}
	m.releaseAll(id)
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
			if s.assigned4.IsValid() {
				delete(m.ipIndex, s.assigned4)
			}
			if s.assigned6.IsValid() {
				delete(m.ipIndex, s.assigned6)
			}
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
	m.ipIndex = map[netip.Addr]*session{}
	m.mu.Unlock()
	for _, s := range victims {
		m.tearDown(s)
	}
}

func (m *mcState) tearDown(s *session) {
	s.mu.Lock()
	if s.isClosed {
		s.mu.Unlock()
		return
	}
	s.isClosed = true
	s.mu.Unlock()
	s.cancel()
	s.closeOnce.Do(func() { close(s.closed) })
	m.releaseAll(s.id)
	if s.userName != "" {
		m.userDB.get().ReleaseSlot(s.userName)
	}
	m.metrics.incSessionClosed()
	m.logger.Printf("session %x: torn down", s.id[:4])
}

func closeAll(qs []PacketIO) {
	for _, q := range qs {
		_ = q.Close()
	}
}

// configureSharedInterface brings the shared TUN up and assigns the
// pool /N and /M directly on it. The kernel treats every client IP
// in the pool as directly connected, so no per-client route is ever
// installed.
func configureSharedInterface(name string, cfg ServerConfig) error {
	if err := exec.Command("ip", "link", "set", name, "up").Run(); err != nil {
		return fmt.Errorf("ip link set up: %w", err)
	}
	if cfg.Subnet.IsValid() && cfg.ServerIP.IsValid() {
		addr := fmt.Sprintf("%s/%d", cfg.ServerIP, cfg.Subnet.Bits())
		if err := exec.Command("ip", "addr", "replace", addr, "dev", name).Run(); err != nil {
			return fmt.Errorf("ip addr replace %s: %w", addr, err)
		}
	}
	if cfg.Subnet6.IsValid() && cfg.ServerIP6.IsValid() {
		addr := fmt.Sprintf("%s/%d", cfg.ServerIP6, cfg.Subnet6.Bits())
		if err := exec.Command("ip", "-6", "addr", "replace", addr, "dev", name).Run(); err != nil {
			return fmt.Errorf("ip -6 addr replace %s: %w", addr, err)
		}
	}
	return nil
}
