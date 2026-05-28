package packethose

import (
	"context"
	"log"
	"math/rand"
	"net"
	"net/netip"
	"time"

	"github.com/flynn/noise"
)

const (
	backoffInitial = 250 * time.Millisecond
	backoffMax     = 30 * time.Second
)

// connSource produces a handshake-completed outer connection paired with its
// lane identity. It blocks until a connection is ready, the context is
// canceled, or a transient error occurs (the supervisor will retry with
// backoff).
type connSource func(ctx context.Context) (net.Conn, laneIdentity, error)

// Assignment carries the server's tunnel-address assignment for one client.
// A family with Prefix == 0 means the server did not assign that family.
type Assignment struct {
	V4Addr   netip.Addr
	V4Prefix byte
	V4Peer   netip.Addr

	V6Addr   netip.Addr
	V6Prefix byte
	V6Peer   netip.Addr
}

// HasV4 reports whether the assignment includes an IPv4 address.
func (a Assignment) HasV4() bool { return a.V4Prefix != 0 && a.V4Addr.IsValid() }

// HasV6 reports whether the assignment includes an IPv6 address.
func (a Assignment) HasV6() bool { return a.V6Prefix != 0 && a.V6Addr.IsValid() }

// onAssignedFn is invoked at most once per supervisor lifetime when the server
// returns any assignment (v4, v6, or both).
type onAssignedFn func(Assignment)

// runSupervised owns one PacketIO and drives outer connections under it,
// acquiring -> running I/O -> reacquiring on any failure, with exponential
// backoff and jitter. The PacketIO stays open for the supervisor's lifetime;
// outer connections come and go beneath it.
func runSupervised(ctx context.Context, id int, pio PacketIO, src connSource, extraTune func(net.Conn), onAssign onAssignedFn, logger *log.Logger) {
	backoff := backoffInitial
	notified := false
	for {
		if ctx.Err() != nil {
			return
		}
		c, ident, err := src(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Printf("lane %d: acquire: %v (retry in ~%s)", id, err, backoff)
			if !sleepJitter(ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}
		backoff = backoffInitial
		// Enable UDP segmentation offload now that the handshake confirmed
		// the peer supports it; this lets the kernel coalesce same-flow UDP
		// like it does TCP. No-op for backends that cannot toggle it.
		if ident.usoEnabled {
			if u, ok := pio.(usoController); ok {
				if err := u.SetUSO(true); err != nil {
					logger.Printf("lane %d: enable USO: %v", id, err)
				}
			}
		}
		logger.Printf("lane %d: up peer=%s encrypted=%v uso=%v", id, c.RemoteAddr(), ident.keys.encrypted, ident.usoEnabled)

		if !notified && onAssign != nil && ident.hasAssignment() {
			onAssign(Assignment{
				V4Addr:   ident.assigned4,
				V4Prefix: ident.prefix4,
				V4Peer:   ident.peer4,
				V6Addr:   ident.assigned6,
				V6Prefix: ident.prefix6,
				V6Peer:   ident.peer6,
			})
			notified = true
		}

		ioDone := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				c.Close()
			case <-ioDone:
			}
		}()

		runLane(pio, c, ident.keys, extraTune, logger)
		close(ioDone)
		logger.Printf("lane %d: down", id)
	}
}

func nextBackoff(d time.Duration) time.Duration {
	n := d * 2
	if n > backoffMax {
		n = backoffMax
	}
	return n
}

// sleepJitter blocks for d + up to d/4 random jitter, or until ctx is done.
// Returns false if the wait was cut short by ctx.
func sleepJitter(ctx context.Context, d time.Duration) bool {
	jitter := time.Duration(rand.Int63n(int64(d/4) + 1))
	t := time.NewTimer(d + jitter)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// clientSource returns a connSource that dials peer over dialer and runs the
// initiate-side handshake. privKey is the client's static private key and
// serverPub is the server's static public key (empty serverPub selects open
// mode). laneCount is the total lanes this client will open (informational on
// the server side); req carries the addresses the client prefers (zero = any).
func clientSource(peer string, privKey, serverPub []byte, cipher Cipher, localUSO bool, dialer ContextDialer, laneCount byte, req AssignmentRequest) connSource {
	return func(ctx context.Context) (net.Conn, laneIdentity, error) {
		c, err := dialer.DialContext(ctx, "tcp", peer)
		if err != nil {
			return nil, laneIdentity{}, err
		}
		if len(serverPub) == 0 {
			// Open mode: no handshake, no encryption.
			return c, laneIdentity{laneCount: laneCount}, nil
		}
		static, err := noiseStatic(privKey)
		if err != nil {
			c.Close()
			return nil, laneIdentity{}, err
		}
		ident, err := initiateHandshake(c, static, serverPub, cipher, localUSO, laneCount, req)
		if err != nil {
			c.Close()
			return nil, laneIdentity{}, err
		}
		return c, ident, nil
	}
}

// serverPool is a small queue of accepted + handshake-validated connections
// waiting to be claimed by lane supervisors. Single-client servers consume
// from a single pool; multi-client servers use per-session pools.
type serverPool struct {
	ready chan acceptedConn
}

type acceptedConn struct {
	c     net.Conn
	ident laneIdentity
}

func newServerPool(cap int) *serverPool {
	return &serverPool{ready: make(chan acceptedConn, cap)}
}

func (p *serverPool) source() connSource {
	return func(ctx context.Context) (net.Conn, laneIdentity, error) {
		select {
		case a := <-p.ready:
			return a.c, a.ident, nil
		case <-ctx.Done():
			return nil, laneIdentity{}, ctx.Err()
		}
	}
}

func runAcceptLoop(ctx context.Context, ln net.Listener, allow string, static noise.DHKey, cipher Cipher, localUSO bool, authorize pubKeyAuthorizer, pool *serverPool, limiter *connLimiter, metrics *Metrics, logger *log.Logger) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Printf("accept: %v", err)
			if !sleepJitter(ctx, 500*time.Millisecond) {
				return
			}
			continue
		}
		metrics.incAccept()
		ip := remoteIP(c)
		if allow != "" && ip != allow {
			logger.Printf("reject %s (allow=%s)", ip, allow)
			c.Close()
			continue
		}
		if !limiter.allowIP(ip) {
			metrics.incRateLimited()
			logger.Printf("rate-limited %s", ip)
			c.Close()
			continue
		}
		if authorize == nil {
			// Open mode: no keys configured, bypass the handshake.
			select {
			case pool.ready <- acceptedConn{c, laneIdentity{}}:
			case <-ctx.Done():
				c.Close()
				return
			}
			continue
		}
		ident, err := acceptHandshake(c, static, cipher, localUSO, authorize, nil)
		if err != nil {
			metrics.incHandshakeFail()
			logger.Printf("handshake fail from %s: %v", c.RemoteAddr(), err)
			c.Close()
			continue
		}
		metrics.incHandshakeOK()
		select {
		case pool.ready <- acceptedConn{c, ident}:
		case <-ctx.Done():
			c.Close()
			return
		}
	}
}

func remoteIP(c net.Conn) string {
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return c.RemoteAddr().String()
	}
	return host
}
