package packethose

import (
	"context"
	"crypto/rand"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Client is a packethose tunnel client. It maintains `Lanes` outer TCP
// connections to the peer, each wired to one of the supplied PacketIO queues.
// Lanes are individually supervised: any lane that drops reconnects with
// exponential backoff while the PacketIO queue stays open.
type Client struct {
	cfg      ClientConfig
	logger   *log.Logger
	clientID [clientIDLen]byte
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
	c := &Client{cfg: cfg, logger: logger}
	if cfg.ClientID != [clientIDLen]byte{} {
		c.clientID = cfg.ClientID
	} else {
		if _, err := rand.Read(c.clientID[:]); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// ClientID returns the stable 16-byte identifier this client sends on every
// lane handshake. Generated randomly on NewClient unless ClientConfig.ClientID
// was set.
func (cl *Client) ClientID() [clientIDLen]byte { return cl.clientID }

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

	reqIP := zeroAddrV4()
	if cl.cfg.RequestIP.IsValid() && cl.cfg.RequestIP.Is4() {
		reqIP = cl.cfg.RequestIP
	}

	src := clientSource(cl.cfg.Peer, cl.cfg.PSK, cl.cfg.Cipher, dialer, cl.clientID, byte(cl.cfg.Lanes), reqIP)

	var assignOnce sync.Once
	onAssign := func(assigned, peer netip.Addr, prefix byte) {
		assignOnce.Do(func() {
			if cl.cfg.OnAssigned != nil {
				cl.cfg.OnAssigned(assigned, peer, prefix)
			}
		})
	}

	var wg sync.WaitGroup
	for i := 0; i < cl.cfg.Lanes; i++ {
		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()
			runSupervised(ctx, i, cl.cfg.Queues[i], src, cl.cfg.TuneSocket, onAssign, cl.logger)
		}()
	}
	wg.Wait()
	return ctx.Err()
}
