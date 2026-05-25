package packethose

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
)

func userCount(db *UserDB) int {
	if db == nil {
		return 0
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	return len(db.byName)
}

// Server is a packethose tunnel server.
//
// Two operating modes:
//
//   1. Single-client (default): Queues is preconfigured, all accepted lanes
//      go to those queues. Suitable for one-to-one tunnels (the basic CLI).
//
//   2. Multi-client (when ServerConfig.Subnet is set): each connecting client
//      is identified by its handshake client-id, assigned a /32 from the
//      pool, and gets its own kernel TUN device. PSK or Users is required.
//      Queues is ignored.
type Server struct {
	cfg    ServerConfig
	logger *log.Logger
	users  *UserDB
}

// NewServer validates cfg and constructs a Server. It does not open the
// listening socket yet; call Run.
func NewServer(cfg ServerConfig) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}
	var db *UserDB
	if len(cfg.Users) > 0 {
		var err error
		db, err = NewUserDB(cfg.Users)
		if err != nil {
			return nil, err
		}
	}
	return &Server{cfg: cfg, logger: logger, users: db}, nil
}

// Run blocks until ctx is canceled or the listener errors fatally.
func (s *Server) Run(ctx context.Context) error {
	lc := s.cfg.ListenConfig
	if lc == nil {
		lc = &net.ListenConfig{}
		if s.cfg.MPTCP {
			lc.SetMultipathTCP(true)
		}
	}
	ln, err := lc.Listen(ctx, "tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.Listen, err)
	}
	defer ln.Close()

	if s.cfg.Subnet.IsValid() || s.cfg.Subnet6.IsValid() {
		if len(s.cfg.PSK) == 0 && (s.users == nil || s.users.Empty()) {
			return fmt.Errorf("packethose server: multi-client mode requires PSK or Users")
		}
		// Build the pool with every configured reservation reserved up
		// front; user-specific quota and ownership are enforced in the
		// assignment hook.
		var resV4, resV6 []netip.Addr
		if s.users != nil {
			resV4, resV6 = s.users.AllReservations()
		}
		var pool4, pool6 *ipPool
		if s.cfg.Subnet.IsValid() {
			reserved := append([]netip.Addr{s.cfg.ServerIP}, resV4...)
			p, err := newIPPool(s.cfg.Subnet, reserved...)
			if err != nil {
				return fmt.Errorf("packethose server: ipPool v4: %w", err)
			}
			pool4 = p
		}
		if s.cfg.Subnet6.IsValid() {
			reserved := append([]netip.Addr{s.cfg.ServerIP6}, resV6...)
			p, err := newIPPool(s.cfg.Subnet6, reserved...)
			if err != nil {
				return fmt.Errorf("packethose server: ipPool v6: %w", err)
			}
			pool6 = p
		}
		s.logger.Printf("listening on %s (multi-client subnet=%s subnet6=%s users=%d allow=%s)",
			s.cfg.Listen, s.cfg.Subnet, s.cfg.Subnet6, userCount(s.users), s.cfg.AllowIP)
		return multiClientLoop(ctx, ln, s.cfg, s.users, pool4, pool6, s.logger)
	}

	s.logger.Printf("listening on %s (mptcp=%v psk=%v users=%d allow=%s lanes=%d)",
		s.cfg.Listen, s.cfg.MPTCP, len(s.cfg.PSK) > 0, userCount(s.users), s.cfg.AllowIP, s.cfg.Lanes)

	pool := newServerPool(s.cfg.Lanes)
	var resolve pskResolver
	if s.users != nil && !s.users.Empty() {
		resolve = userDBResolver(s.users, s.cfg.PSK)
	} else if len(s.cfg.PSK) > 0 {
		resolve = singlePSKResolver(s.cfg.PSK)
	}
	go runAcceptLoop(ctx, ln, s.cfg.AllowIP, resolve, pool, s.logger)

	var wg sync.WaitGroup
	for i := 0; i < s.cfg.Lanes; i++ {
		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()
			runSupervised(ctx, i, s.cfg.Queues[i], pool.source(), s.cfg.TuneSocket, nil, s.logger)
		}()
	}
	wg.Wait()
	return ctx.Err()
}
