package packethose

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
)

// Server is a packethose tunnel server.
//
// Two operating modes:
//
//   1. Single-client (default): Queues is preconfigured, all accepted lanes
//      go to those queues. Suitable for one-to-one tunnels (the basic CLI).
//
//   2. Multi-client (when ServerConfig.Subnet is set): each connecting client
//      is identified by its handshake client-id, assigned a /32 from the
//      pool, and gets its own kernel TUN device. PSK is required. Queues is
//      ignored.
type Server struct {
	cfg    ServerConfig
	logger *log.Logger
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
	return &Server{cfg: cfg, logger: logger}, nil
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
		if len(s.cfg.PSK) == 0 {
			return fmt.Errorf("packethose server: multi-client mode requires PSK")
		}
		var pool4, pool6 *ipPool
		if s.cfg.Subnet.IsValid() {
			p, err := newIPPool(s.cfg.Subnet, s.cfg.ServerIP)
			if err != nil {
				return fmt.Errorf("packethose server: ipPool v4: %w", err)
			}
			pool4 = p
		}
		if s.cfg.Subnet6.IsValid() {
			p, err := newIPPool(s.cfg.Subnet6, s.cfg.ServerIP6)
			if err != nil {
				return fmt.Errorf("packethose server: ipPool v6: %w", err)
			}
			pool6 = p
		}
		s.logger.Printf("listening on %s (multi-client subnet=%s subnet6=%s allow=%s)",
			s.cfg.Listen, s.cfg.Subnet, s.cfg.Subnet6, s.cfg.AllowIP)
		return multiClientLoop(ctx, ln, s.cfg, pool4, pool6, s.logger)
	}

	s.logger.Printf("listening on %s (mptcp=%v psk=%v allow=%s lanes=%d)",
		s.cfg.Listen, s.cfg.MPTCP, len(s.cfg.PSK) > 0, s.cfg.AllowIP, s.cfg.Lanes)

	pool := newServerPool(s.cfg.Lanes)
	go runAcceptLoop(ctx, ln, s.cfg.AllowIP, s.cfg.PSK, pool, s.logger)

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
