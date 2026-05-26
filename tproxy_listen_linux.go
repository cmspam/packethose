//go:build linux

package packethose

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// TPROXYListener terminates client TCP and UDP flows redirected by
// the nftables prerouting hook.
//
// TCP: accept the redirected connection (LocalAddr() is the original
// destination because the listener is IP_TRANSPARENT), tune both the
// accepted socket and the outbound dial for high-throughput
// forwarding (BBR, 4 MiB buffers, TCP_NODELAY, keepalive), then let
// the Go runtime splice() bytes between the two *net.TCPConn ends.
//
// UDP: a single recvmsg loop fans incoming datagrams out to per-flow
// state. Each flow holds a *connected* upstream UDP socket (so the
// kernel skips per-packet routing lookup), an IP_TRANSPARENT reply
// socket bound to the original destination (so the client sees
// responses from the IP it tried to reach), and a sync.Pool-backed
// buffer reuse so the data plane allocates nothing per packet.
type TPROXYListener struct {
	cfg    TPROXYConfig
	logger *log.Logger

	tcpLn  net.Listener
	udpPC  net.PacketConn
	closed chan struct{}
	wg     sync.WaitGroup
}

// udpBufPool reuses 64 KiB buffers across UDP recvs to avoid per-
// packet allocation pressure in the data plane.
var udpBufPool = sync.Pool{
	New: func() any { b := make([]byte, 65535); return &b },
}

// NewTPROXYListener validates cfg and returns a listener. Call Start
// to bind the sockets.
func NewTPROXYListener(cfg TPROXYConfig, logger *log.Logger) (*TPROXYListener, error) {
	if logger == nil {
		logger = log.Default()
	}
	if !cfg.Enabled {
		return &TPROXYListener{cfg: cfg, logger: logger, closed: make(chan struct{})}, nil
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "0.0.0.0"
	}
	if cfg.ListenPort == 0 {
		cfg.ListenPort = 13338
	}
	if cfg.UDPIdleTimeout <= 0 {
		cfg.UDPIdleTimeout = 60 * time.Second
	}
	return &TPROXYListener{cfg: cfg, logger: logger, closed: make(chan struct{})}, nil
}

// Start opens the TCP and UDP TPROXY sockets and runs the accept
// goroutines. Returns immediately once the sockets are bound.
func (t *TPROXYListener) Start(ctx context.Context) error {
	if !t.cfg.Enabled {
		return nil
	}
	addr := net.JoinHostPort(t.cfg.ListenAddr, strconv.Itoa(t.cfg.ListenPort))

	lc := net.ListenConfig{Control: tproxyTCPControl}
	tcpLn, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("tproxy tcp listen %s: %w", addr, err)
	}
	t.tcpLn = tcpLn

	udpLC := net.ListenConfig{Control: tproxyUDPControl}
	udpPC, err := udpLC.ListenPacket(ctx, "udp", addr)
	if err != nil {
		_ = tcpLn.Close()
		return fmt.Errorf("tproxy udp listen %s: %w", addr, err)
	}
	t.udpPC = udpPC

	t.logger.Printf("tproxy: listening on %s (isolation=%v pool4=%s pool6=%s bbr=%v)",
		addr, t.cfg.EnforceIsolation, t.cfg.PoolV4, t.cfg.PoolV6, BBRAvailable())

	t.wg.Add(2)
	go t.tcpAcceptLoop(ctx)
	go t.udpAcceptLoop(ctx)
	return nil
}

// Stop closes the listening sockets and waits for the accept and
// flow goroutines to drain.
func (t *TPROXYListener) Stop() {
	if !t.cfg.Enabled {
		return
	}
	select {
	case <-t.closed:
	default:
		close(t.closed)
	}
	if t.tcpLn != nil {
		_ = t.tcpLn.Close()
	}
	if t.udpPC != nil {
		_ = t.udpPC.Close()
	}
	t.wg.Wait()
}

// tproxyTCPControl arms the TCP listening socket for redirected
// flows: IP_TRANSPARENT so SYNs for non-local destinations land here,
// SO_REUSEADDR so restarts don't TIME_WAIT-block.
func tproxyTCPControl(network, address string, c syscall.RawConn) error {
	var setErr error
	err := c.Control(func(fd uintptr) {
		e4 := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TRANSPARENT, 1)
		e6 := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_TRANSPARENT, 1)
		if e4 != nil && e6 != nil {
			setErr = e4
			return
		}
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	})
	if err != nil {
		return err
	}
	return setErr
}

// tproxyUDPControl mirrors tproxyTCPControl for UDP and additionally
// asks the kernel to deliver the original-destination cmsg with each
// recvmsg.
func tproxyUDPControl(network, address string, c syscall.RawConn) error {
	var setErr error
	err := c.Control(func(fd uintptr) {
		e4 := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TRANSPARENT, 1)
		e6 := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_TRANSPARENT, 1)
		if e4 != nil && e6 != nil {
			setErr = e4
			return
		}
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVORIGDSTADDR, 1)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		// 8 MiB recv buffer absorbs bursts from many concurrent flows
		// while the userspace loop catches up. Without this the kernel
		// drops on burst overflow at default ~256 KB.
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, 8<<20)
	})
	if err != nil {
		return err
	}
	return setErr
}

// tuneTCP applies the per-flow socket options that turn an ordinary
// forwarded TCP connection into a high-throughput one: BBR
// congestion control (kernel default is often cubic, which underruns
// long fat pipes), 4 MiB send + recv buffers (kernel autotunes but
// the floor is sometimes too low), TCP_NODELAY (no Nagle delay since
// we may be carrying interactive bytes), keepalive to drop dead
// peers. Errors are deliberately swallowed: failing to tune doesn't
// break the forward; it just leaves performance on the table.
func tuneTCP(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetNoDelay(true)
	_ = tc.SetKeepAlive(true)
	_ = tc.SetKeepAlivePeriod(30 * time.Second)
	sc, err := tc.SyscallConn()
	if err != nil {
		return
	}
	_ = sc.Control(func(fd uintptr) {
		// 4 MiB each direction. Linux silently caps at
		// net.core.{r,w}mem_max, which is 4 MiB on most distros and
		// boosted to 32 MiB on our bench hosts; setting 4 MiB is a
		// reasonable floor without needing operator tuning.
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, 4<<20)
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)
		// TCP_USER_TIMEOUT: kill the conn after 30s of no ACK so a
		// stalled forward doesn't pin resources indefinitely.
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, 30000)
	})
	_ = applyBBR(c)
}

// tunedTCPDialer returns a *net.Dialer that arms outgoing TCP sockets
// with BBR and large buffers via the Control hook, so the tuning is
// in effect from the very first SYN (cwnd ramps faster).
func tunedTCPDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, 4<<20)
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)
				if bbrAvailable() {
					_ = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, "bbr")
				}
			})
		},
	}
}

func (t *TPROXYListener) tcpAcceptLoop(ctx context.Context) {
	defer t.wg.Done()
	for {
		conn, err := t.tcpLn.Accept()
		if err != nil {
			select {
			case <-t.closed:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			t.logger.Printf("tproxy tcp: accept: %v", err)
			continue
		}
		go t.handleTCP(ctx, conn)
	}
}

// handleTCP runs one accepted client flow. The accepted socket's
// LocalAddr() is the original destination (TPROXY preserves it).
// Both the client-side and upstream-side TCPConns are tuned before
// io.Copy engages splice(2) on the pair.
func (t *TPROXYListener) handleTCP(ctx context.Context, client net.Conn) {
	defer client.Close()
	dst, err := originalTCPDst(client)
	if err != nil {
		t.logger.Printf("tproxy tcp: original-dst: %v", err)
		return
	}
	if t.cfg.EnforceIsolation && t.inPool(dst.Addr()) {
		return
	}
	tuneTCP(client)
	upstream, err := tunedTCPDialer(10 * time.Second).DialContext(ctx, "tcp", dst.String())
	if err != nil {
		return
	}
	defer upstream.Close()
	tuneTCP(upstream)
	relayTCP(client, upstream)
}

// originalTCPDst returns the destination address the client tried to
// reach before nftables redirected the connection. For a TPROXY'd
// listener the original destination is preserved on LocalAddr().
func originalTCPDst(conn net.Conn) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(conn.LocalAddr().String())
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("parse local addr: %w", err)
	}
	return ap, nil
}

// relayTCP joins two TCP connections with io.Copy on each direction.
// Go's runtime recognises *net.TCPConn pairs and substitutes splice(2)
// so byte movement stays entirely in the kernel; no userspace buffer.
func relayTCP(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(b, a)
		closeWrite(b)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(a, b)
		closeWrite(a)
		done <- struct{}{}
	}()
	<-done
	<-done
}

func closeWrite(c net.Conn) {
	type cw interface{ CloseWrite() error }
	if x, ok := c.(cw); ok {
		_ = x.CloseWrite()
		return
	}
	_ = c.Close()
}

// inPool reports whether addr falls inside either configured pool
// subnet, excluding the server's own tunnel IPs.
func (t *TPROXYListener) inPool(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	if t.cfg.ServerIP4.IsValid() && addr == t.cfg.ServerIP4 {
		return false
	}
	if t.cfg.ServerIP6.IsValid() && addr == t.cfg.ServerIP6 {
		return false
	}
	if t.cfg.PoolV4.IsValid() && t.cfg.PoolV4.Contains(addr) {
		return true
	}
	if t.cfg.PoolV6.IsValid() && t.cfg.PoolV6.Contains(addr) {
		return true
	}
	return false
}

// tproxyUDPFlow is one active (src, dst) UDP session. The upstream
// socket is *connected* to dst: the kernel resolves the route once at
// connect time and reuses it for every send, skipping per-packet
// route lookup. The reply socket is IP_TRANSPARENT-bound to dst so
// the client sees responses from the address it tried to reach.
type tproxyUDPFlow struct {
	src          netip.AddrPort
	dst          netip.AddrPort
	upstream     *net.UDPConn
	reply        *net.UDPConn
	clientAddr   *net.UDPAddr
	lastActivity atomic.Int64 // unix-nano of most recent traffic
	closed       atomic.Bool
	closeCh      chan struct{}
	closeOnce    sync.Once
}

func (f *tproxyUDPFlow) bump() { f.lastActivity.Store(time.Now().UnixNano()) }

func (f *tproxyUDPFlow) shutdown() {
	f.closeOnce.Do(func() {
		f.closed.Store(true)
		close(f.closeCh)
		_ = f.upstream.Close()
		_ = f.reply.Close()
	})
}

func (t *TPROXYListener) udpAcceptLoop(ctx context.Context) {
	defer t.wg.Done()
	udpConn, ok := t.udpPC.(*net.UDPConn)
	if !ok {
		t.logger.Printf("tproxy udp: PacketConn is not *net.UDPConn")
		return
	}
	sc, err := udpConn.SyscallConn()
	if err != nil {
		t.logger.Printf("tproxy udp: SyscallConn: %v", err)
		return
	}

	flowsMu := sync.Mutex{}
	flows := map[string]*tproxyUDPFlow{}

	// Pre-allocated buffers for the accept-loop's recv path. The
	// payload buffer is pooled separately so it can travel with the
	// per-flow write op without holding the accept-loop hostage.
	cbuf := make([]byte, 1024)
	for {
		select {
		case <-t.closed:
			return
		default:
		}
		_ = udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))

		bufPtr := udpBufPool.Get().(*[]byte)
		buf := *bufPtr
		var n, oobn int
		var srcSA unix.Sockaddr
		var rerr error
		cerr := sc.Read(func(fd uintptr) bool {
			n, oobn, _, srcSA, rerr = unix.Recvmsg(int(fd), buf, cbuf, 0)
			return !errors.Is(rerr, unix.EAGAIN) && !errors.Is(rerr, unix.EWOULDBLOCK)
		})
		if cerr != nil {
			rerr = cerr
		}
		if rerr != nil {
			udpBufPool.Put(bufPtr)
			select {
			case <-t.closed:
				return
			default:
			}
			if errors.Is(rerr, net.ErrClosed) {
				return
			}
			var ne net.Error
			if errors.As(rerr, &ne) && ne.Timeout() {
				continue
			}
			if errors.Is(rerr, unix.EAGAIN) {
				continue
			}
			continue
		}
		if n <= 0 {
			udpBufPool.Put(bufPtr)
			continue
		}
		src := sockaddrToAddrPort(srcSA)
		dst, dstOK := origDstFromCmsg(cbuf[:oobn])
		if !dstOK {
			udpBufPool.Put(bufPtr)
			continue
		}
		if t.cfg.EnforceIsolation && t.inPool(dst.Addr()) {
			udpBufPool.Put(bufPtr)
			continue
		}
		key := src.String() + "|" + dst.String()

		flowsMu.Lock()
		flow, exists := flows[key]
		if !exists {
			f, err := t.openUDPFlow(ctx, src, dst)
			if err != nil {
				flowsMu.Unlock()
				udpBufPool.Put(bufPtr)
				continue
			}
			flow = f
			flows[key] = f
			t.wg.Add(1)
			go t.runUDPReplyPump(ctx, f, &flowsMu, flows, key)
		}
		flow.bump()
		flowsMu.Unlock()

		// Connected upstream socket: kernel knows where these bytes
		// are going, no per-packet route lookup. Direct write from
		// the accept loop avoids the channel hop and the second
		// allocation we used to do.
		_, _ = flow.upstream.Write(buf[:n])
		udpBufPool.Put(bufPtr)
	}
}

// openUDPFlow allocates a per-flow connected upstream socket and a
// per-flow IP_TRANSPARENT reply socket. Connected upstream skips
// per-packet routing; reply is bound to dst so client sees the right
// source on replies.
func (t *TPROXYListener) openUDPFlow(ctx context.Context, src, dst netip.AddrPort) (*tproxyUDPFlow, error) {
	dstAddr := &net.UDPAddr{IP: dst.Addr().AsSlice(), Port: int(dst.Port())}
	upstreamRaw, err := net.DialUDP("udp", nil, dstAddr)
	if err != nil {
		return nil, err
	}
	// Big UDP buffers so a bursty server reply doesn't drop in the
	// kernel before we read.
	if sc, err := upstreamRaw.SyscallConn(); err == nil {
		_ = sc.Control(func(fd uintptr) {
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, 4<<20)
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)
		})
	}

	replyLC := net.ListenConfig{Control: tproxyUDPControl}
	replyPC, err := replyLC.ListenPacket(ctx, "udp", dstAddr.String())
	if err != nil {
		_ = upstreamRaw.Close()
		return nil, err
	}
	reply, ok := replyPC.(*net.UDPConn)
	if !ok {
		_ = replyPC.Close()
		_ = upstreamRaw.Close()
		return nil, fmt.Errorf("tproxy udp reply: PacketConn not *net.UDPConn")
	}
	clientAddr := &net.UDPAddr{IP: src.Addr().AsSlice(), Port: int(src.Port())}

	f := &tproxyUDPFlow{
		src:        src,
		dst:        dst,
		upstream:   upstreamRaw,
		reply:      reply,
		clientAddr: clientAddr,
		closeCh:    make(chan struct{}),
	}
	f.bump()
	return f, nil
}

// runUDPReplyPump pulls server→client packets off the upstream socket
// and sprays them back to the client via the IP_TRANSPARENT reply
// socket. One goroutine per flow handles only this direction; the
// client→server direction is handled inline by the accept loop using
// the connected upstream socket. This halves the goroutine count
// vs the per-direction model and removes the queue-channel copy.
//
// Exit conditions: idle timeout (no traffic for cfg.UDPIdleTimeout),
// upstream socket closed, or listener shutdown.
func (t *TPROXYListener) runUDPReplyPump(ctx context.Context, f *tproxyUDPFlow, mu *sync.Mutex, flows map[string]*tproxyUDPFlow, key string) {
	defer t.wg.Done()
	defer func() {
		mu.Lock()
		if flows[key] == f {
			delete(flows, key)
		}
		mu.Unlock()
		f.shutdown()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.closed:
			return
		case <-f.closeCh:
			return
		default:
		}
		// Recompute the idle deadline from lastActivity. The accept
		// loop bumps on every client packet and we bump here on each
		// upstream packet, so the deadline accurately tracks the
		// most recent traffic in either direction.
		last := time.Unix(0, f.lastActivity.Load())
		deadline := last.Add(t.cfg.UDPIdleTimeout)
		if !deadline.After(time.Now()) {
			return // genuinely idle past timeout
		}
		_ = f.upstream.SetReadDeadline(deadline)

		bufPtr := udpBufPool.Get().(*[]byte)
		buf := *bufPtr
		n, _, err := f.upstream.ReadFromUDP(buf)
		if err != nil {
			udpBufPool.Put(bufPtr)
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				// Could be activity-bump while we were blocked. Loop
				// to recompute the deadline.
				continue
			}
			return
		}
		if n <= 0 {
			udpBufPool.Put(bufPtr)
			continue
		}
		f.bump()
		_, _ = f.reply.WriteToUDP(buf[:n], f.clientAddr)
		udpBufPool.Put(bufPtr)
	}
}

func sockaddrToAddrPort(sa unix.Sockaddr) netip.AddrPort {
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		return netip.AddrPortFrom(netip.AddrFrom4(a.Addr), uint16(a.Port))
	case *unix.SockaddrInet6:
		return netip.AddrPortFrom(netip.AddrFrom16(a.Addr), uint16(a.Port))
	}
	return netip.AddrPort{}
}

func origDstFromCmsg(cbuf []byte) (netip.AddrPort, bool) {
	msgs, err := unix.ParseSocketControlMessage(cbuf)
	if err != nil {
		return netip.AddrPort{}, false
	}
	for _, m := range msgs {
		if m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_ORIGDSTADDR {
			if len(m.Data) < 8 {
				continue
			}
			port := binary.BigEndian.Uint16(m.Data[2:4])
			var v4 [4]byte
			copy(v4[:], m.Data[4:8])
			return netip.AddrPortFrom(netip.AddrFrom4(v4), port), true
		}
		if m.Header.Level == unix.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_ORIGDSTADDR {
			if len(m.Data) < 24 {
				continue
			}
			port := binary.BigEndian.Uint16(m.Data[2:4])
			var v6 [16]byte
			copy(v6[:], m.Data[8:24])
			return netip.AddrPortFrom(netip.AddrFrom16(v6), port), true
		}
	}
	return netip.AddrPort{}, false
}
