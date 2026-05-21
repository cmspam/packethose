package packethose

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
)

// Server is a packethose tunnel server. It listens for inbound lane
// connections, validates each (allowlist + handshake), and assigns them to
// supervised lane slots backed by the configured PacketIO queues.
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
			runSupervised(ctx, i, s.cfg.Queues[i], pool.source(), s.cfg.TuneSocket, s.logger)
		}()
	}
	wg.Wait()
	return ctx.Err()
}
