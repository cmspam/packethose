package packethose

import (
	"context"
	"crypto/rand"
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
// lane handshake.
func (cl *Client) ClientID() [clientIDLen]byte { return cl.clientID }

// Run blocks until ctx is canceled.
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

	req := AssignmentRequest{}
	if cl.cfg.RequestIP.IsValid() && cl.cfg.RequestIP.Is4() {
		req.V4 = cl.cfg.RequestIP
	}
	if cl.cfg.RequestIP6.IsValid() && cl.cfg.RequestIP6.Is6() {
		req.V6 = cl.cfg.RequestIP6
	}

	src := clientSource(cl.cfg.Peer, cl.cfg.PSK, cl.cfg.Cipher, dialer, cl.clientID, byte(cl.cfg.Lanes), req)

	var assignOnce sync.Once
	onAssign := func(a Assignment) {
		assignOnce.Do(func() {
			if cl.cfg.OnAssigned != nil {
				cl.cfg.OnAssigned(a)
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
