package packethose

import (
	"context"
	"log"
	"net"
	"sync"
	"time"
)

// Client is a packethose tunnel client. It maintains `Lanes` outer TCP
// connections to the peer, each wired to one of the supplied PacketIO queues.
// Lanes are individually supervised: any lane that drops reconnects with
// exponential backoff while the PacketIO queue stays open.
type Client struct {
	cfg    ClientConfig
	logger *log.Logger
}

// NewClient validates cfg and constructs a Client. It does not open
// connections yet; call Run.
func NewClient(cfg ClientConfig) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}
	return &Client{cfg: cfg, logger: logger}, nil
}

// Run blocks until ctx is canceled. All lane supervisors run in goroutines;
// Run returns once they have all exited.
func (cl *Client) Run(ctx context.Context) error {
	dialer := cl.cfg.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 10 * time.Second}
	}
	if cl.cfg.MPTCP {
		if d, ok := dialer.(*net.Dialer); ok {
			d.SetMultipathTCP(true)
		}
	}
	src := clientSource(cl.cfg.Peer, cl.cfg.PSK, cl.cfg.Cipher, dialer)

	var wg sync.WaitGroup
	for i := 0; i < cl.cfg.Lanes; i++ {
		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()
			runSupervised(ctx, i, cl.cfg.Queues[i], src, cl.cfg.TuneSocket, cl.logger)
		}()
	}
	wg.Wait()
	return ctx.Err()
}
