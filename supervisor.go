package packethose

import (
	"context"
	"log"
	"math/rand"
	"net"
	"time"
)

const (
	backoffInitial = 250 * time.Millisecond
	backoffMax     = 30 * time.Second
)

// connSource produces a handshake-completed outer connection paired with its
// session keys. It blocks until a connection is ready, the context is canceled,
// or a transient error occurs (the supervisor will retry with backoff).
type connSource func(ctx context.Context) (net.Conn, laneKeys, error)

// runSupervised owns one PacketIO and drives outer connections under it,
// acquiring -> running I/O -> reacquiring on any failure, with exponential
// backoff and jitter. The PacketIO stays open for the supervisor's lifetime;
// outer connections come and go beneath it.
//
// Cancel ctx to shut the supervisor down. The active outer connection is
// closed, in-flight I/O unblocks, and the loop returns.
func runSupervised(ctx context.Context, id int, pio PacketIO, src connSource, extraTune func(net.Conn), logger *log.Logger) {
	backoff := backoffInitial
	for {
		if ctx.Err() != nil {
			return
		}
		c, keys, err := src(ctx)
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
		logger.Printf("lane %d: up peer=%s cipher=%s", id, c.RemoteAddr(), keys.kind)

		// Unblock I/O on shutdown by closing the conn.
		ioDone := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				c.Close()
			case <-ioDone:
			}
		}()

		runLane(pio, c, keys, extraTune, logger)
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
// initiate-side handshake.
func clientSource(peer string, psk []byte, cipher Cipher, dialer ContextDialer) connSource {
	return func(ctx context.Context) (net.Conn, laneKeys, error) {
		c, err := dialer.DialContext(ctx, "tcp", peer)
		if err != nil {
			return nil, laneKeys{}, err
		}
		keys, err := initiateHandshake(c, psk, cipher)
		if err != nil {
			c.Close()
			return nil, laneKeys{}, err
		}
		return c, keys, nil
	}
}

// serverPool is a small queue of accepted+handshaked connections waiting to be
// claimed by lane supervisors. Lanes are symmetric so any incoming connection
// can fill any waiting lane slot.
type serverPool struct {
	ready chan acceptedConn
}

type acceptedConn struct {
	c    net.Conn
	keys laneKeys
}

func newServerPool(cap int) *serverPool {
	return &serverPool{ready: make(chan acceptedConn, cap)}
}

func (p *serverPool) source() connSource {
	return func(ctx context.Context) (net.Conn, laneKeys, error) {
		select {
		case a := <-p.ready:
			return a.c, a.keys, nil
		case <-ctx.Done():
			return nil, laneKeys{}, ctx.Err()
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
		keys, err := acceptHandshake(c, psk)
		if err != nil {
			logger.Printf("handshake fail from %s: %v", c.RemoteAddr(), err)
			c.Close()
			continue
		}
		select {
		case pool.ready <- acceptedConn{c, keys}:
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
