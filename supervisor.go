package packethose

import (
	"context"
	"log"
	"math/rand"
	"net"
	"net/netip"
	"time"
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
		logger.Printf("lane %d: up peer=%s cipher=%s", id, c.RemoteAddr(), ident.keys.kind)

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
// initiate-side handshake. clientID identifies this client; laneCount is the
// total lanes this client will open (informational on server side). userName
// is the on-wire identity used to select the matching PSK on the server.
// reqIP is the IP the client prefers to be assigned (zero = any).
func clientSource(peer string, psk []byte, cipher Cipher, dialer ContextDialer, userName string, clientID [clientIDLen]byte, laneCount byte, req AssignmentRequest) connSource {
	return func(ctx context.Context) (net.Conn, laneIdentity, error) {
		c, err := dialer.DialContext(ctx, "tcp", peer)
		if err != nil {
			return nil, laneIdentity{}, err
		}
		ident, err := initiateHandshake(c, psk, cipher, userName, clientID, laneCount, req)
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

func runAcceptLoop(ctx context.Context, ln net.Listener, allow string, resolve pskResolver, pool *serverPool, logger *log.Logger) {
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
		if allow != "" {
			if ip := remoteIP(c); ip != allow {
				logger.Printf("reject %s (allow=%s)", ip, allow)
				c.Close()
				continue
			}
		}
		if resolve == nil {
			// No PSK configured: bypass the handshake entirely.
			select {
			case pool.ready <- acceptedConn{c, laneIdentity{}}:
			case <-ctx.Done():
				c.Close()
				return
			}
			continue
		}
		ident, err := acceptHandshake(c, resolve, nil)
		if err != nil {
			logger.Printf("handshake fail from %s: %v", c.RemoteAddr(), err)
			c.Close()
			continue
		}
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
