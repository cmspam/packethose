package packethose

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"

	"github.com/flynn/noise"
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
//  1. Single-client (default): Queues is preconfigured, all accepted lanes
//     go to those queues. Suitable for one-to-one tunnels (the basic CLI).
//
//  2. Multi-client (when ServerConfig.Subnet is set): each connecting client
//     is authorized by its static public key, assigned an address from the
//     pool, and routed over the shared TUN device. A server static key and
//     at least one authorized client key are required. Queues is ignored.
type Server struct {
	cfg     ServerConfig
	logger  *log.Logger
	users   *UserDB       // initial set, used for pool reservations at startup
	userDB  *userDBHolder // live, hot-reloadable authorized-client set
	metrics *Metrics
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
	var metrics *Metrics
	if cfg.MetricsAddr != "" {
		metrics = NewMetrics()
	}
	return &Server{cfg: cfg, logger: logger, users: db, userDB: newUserDBHolder(db), metrics: metrics}, nil
}

// ReloadUsers swaps the authorized-client set without restarting. It
// updates which client keys are accepted and their quotas; it does not
// re-derive pool reservations (those are fixed at startup). Live
// sessions are unaffected. Safe to call concurrently with serving.
func (s *Server) ReloadUsers(users []User) error {
	db, err := NewUserDB(users)
	if err != nil {
		return err
	}
	s.userDB.set(db)
	s.logger.Printf("reloaded %d authorized client keys", userCount(db))
	return nil
}

// Run blocks until ctx is canceled or the listener errors fatally.
func (s *Server) Run(ctx context.Context) error {
	// Bring up the auto-installed nftables before we accept any
	// connections so the first packet a client sends is already
	// covered by the forwarding posture. Reconcile tolerates a stale
	// table from a previous ungraceful exit.
	var nftInstaller *NFTInstaller
	if s.cfg.NFT.Enabled {
		ni, err := NewNFTInstaller(s.cfg.NFT, s.logger)
		if err != nil {
			return fmt.Errorf("packethose server: nft installer: %w", err)
		}
		if err := ni.Reconcile(); err != nil {
			return fmt.Errorf("packethose server: nft reconcile: %w", err)
		}
		nftInstaller = ni
		defer func() {
			if err := nftInstaller.Remove(); err != nil {
				s.logger.Printf("nft: remove on shutdown: %v", err)
			}
		}()
	}

	// TPROXY termination listener: runs alongside the tunnel server
	// so traffic redirected by the prerouting hook lands here.
	var tproxyListener *TPROXYListener
	if s.cfg.TPROXY.Enabled {
		tl, err := NewTPROXYListener(s.cfg.TPROXY, s.logger)
		if err != nil {
			return fmt.Errorf("packethose server: tproxy listener: %w", err)
		}
		if err := tl.Start(ctx); err != nil {
			return fmt.Errorf("packethose server: tproxy start: %w", err)
		}
		tproxyListener = tl
		defer tproxyListener.Stop()
	}

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

	if s.metrics != nil {
		if nftInstaller != nil && s.cfg.NFT.Accounting {
			ni := nftInstaller
			s.metrics.SetStatProvider(func() []ByteStat {
				cs, err := ni.Stats()
				if err != nil {
					return nil
				}
				out := make([]ByteStat, 0, len(cs))
				for _, c := range cs {
					out = append(out, ByteStat{Addr: c.Addr.String(), TxBytes: c.UpBytes, RxBytes: c.DownBytes})
				}
				return out
			})
		}
		go serveMetrics(ctx, s.cfg.MetricsAddr, s.metrics, s.logger)
	}

	if s.cfg.Subnet.IsValid() || s.cfg.Subnet6.IsValid() {
		static, err := noiseStatic(s.cfg.StaticPrivateKey)
		if err != nil {
			return fmt.Errorf("packethose server: static key: %w", err)
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
		return multiClientLoop(ctx, ln, s.cfg, s.userDB, static, pool4, pool6, s.metrics, s.logger)
	}

	s.logger.Printf("listening on %s (mptcp=%v keyed=%v users=%d allow=%s lanes=%d)",
		s.cfg.Listen, s.cfg.MPTCP, s.cfg.keyed(), userCount(s.users), s.cfg.AllowIP, s.cfg.Lanes)

	pool := newServerPool(s.cfg.Lanes)
	var static noise.DHKey
	var authorize pubKeyAuthorizer
	if s.cfg.keyed() {
		var err error
		if static, err = noiseStatic(s.cfg.StaticPrivateKey); err != nil {
			return fmt.Errorf("packethose server: static key: %w", err)
		}
		authorize = serverAuthorizer(s.userDB.get(), s.cfg.PeerPublicKey)
	}
	go runAcceptLoop(ctx, ln, s.cfg.AllowIP, static, s.cfg.Cipher, localUSO(s.cfg.Queues), authorize, pool, newConnLimiter(s.cfg.RateLimit), s.metrics, s.logger)

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
