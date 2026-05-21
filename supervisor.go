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

// onAssigned is invoked on the FIRST successful handshake from a supervisor's
// lane if the server returned a non-zero assigned IP. It is called at most
// once per supervisor lifetime.
type onAssigned func(assigned netip.Addr, peer netip.Addr, prefix byte)

// runSupervised owns one PacketIO and drives outer connections under it,
// acquiring -> running I/O -> reacquiring on any failure, with exponential
// backoff and jitter. The PacketIO stays open for the supervisor's lifetime;
// outer connections come and go beneath it.
func runSupervised(ctx context.Context, id int, pio PacketIO, src connSource, extraTune func(net.Conn), onAssign onAssigned, logger *log.Logger) {
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

		if !notified && onAssign != nil && ident.prefixLen != 0 {
			onAssign(ident.assignedIP, ident.peerIP, ident.prefixLen)
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
// total lanes this client will open (informational on server side). reqIP is
// the IP the client prefers to be assigned (zero = any).
func clientSource(peer string, psk []byte, cipher Cipher, dialer ContextDialer, clientID [clientIDLen]byte, laneCount byte, reqIP netip.Addr) connSource {
	return func(ctx context.Context) (net.Conn, laneIdentity, error) {
		c, err := dialer.DialContext(ctx, "tcp", peer)
		if err != nil {
			return nil, laneIdentity{}, err
		}
		ident, err := initiateHandshake(c, psk, cipher, clientID, laneCount, reqIP)
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

func runAcceptLoop(ctx context.Context, ln net.Listener, allow string, psk []byte, pool *serverPool, logger *log.Logger) {
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
		ident, err := acceptHandshake(c, psk, nil)
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
