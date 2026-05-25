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
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// TPROXYListener terminates client TCP and UDP flows redirected by
// the nftables prerouting hook. For TCP it accepts the redirected
// connection, retrieves the original destination via SO_ORIGINAL_DST
// (v4) or IP6T_SO_ORIGINAL_DST (v6), dials that destination directly,
// and splices the two TCPConn endpoints with io.Copy so the Go
// runtime engages splice(). For UDP it demultiplexes per source/dst
// flow and forwards via an unconnected UDP socket; replies traverse
// a per-flow IP_TRANSPARENT socket bound to the original destination
// so the client sees responses from the right source.
type TPROXYListener struct {
	cfg    TPROXYConfig
	logger *log.Logger

	tcpLn  net.Listener
	udpPC  net.PacketConn
	closed chan struct{}
	wg     sync.WaitGroup
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

	t.logger.Printf("tproxy: listening on %s (isolation=%v pool4=%s pool6=%s)",
		addr, t.cfg.EnforceIsolation, t.cfg.PoolV4, t.cfg.PoolV6)

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

// tproxyTCPControl sets IP_TRANSPARENT (and IPV6_TRANSPARENT when the
// kernel accepts it) on the TCP listening socket so the kernel
// delivers redirected SYNs to this socket instead of the real
// destination's port.
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
	})
	if err != nil {
		return err
	}
	return setErr
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

// handleTCP runs one accepted client flow: read the original
// destination, optionally reject by isolation, dial out, splice both
// ends. The client side is a redirected accept so LocalAddr() returns
// the original destination already; SO_ORIGINAL_DST is needed only on
// nf_conntrack REDIRECT, not on TPROXY. We still recover via
// LocalAddr.
func (t *TPROXYListener) handleTCP(ctx context.Context, client net.Conn) {
	defer client.Close()
	dst, err := originalTCPDst(client)
	if err != nil {
		t.logger.Printf("tproxy tcp: original-dst: %v", err)
		return
	}
	if t.cfg.EnforceIsolation && t.inPool(dst.Addr()) {
		// Inter-client traffic. Drop silently; clients see RST.
		return
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	upstream, err := dialer.DialContext(ctx, "tcp", dst.String())
	if err != nil {
		return
	}
	defer upstream.Close()
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
// subnet, excluding the server's own tunnel IPs. The server's IP is
// in the pool subnet by definition; without this exemption the
// isolation gate would forbid clients from reaching services bound
// to the server's tunnel IP, breaking iperf3 to the server,
// administrative sshd, etc.
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

// tproxyUDPFlow is one active (src, dst) UDP session.
type tproxyUDPFlow struct {
	src      netip.AddrPort
	dst      netip.AddrPort
	queue    chan []byte
	upstream net.PacketConn
	reply    net.PacketConn
	done     chan struct{}
	closeOne sync.Once
	lastSeen time.Time
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

	buf := make([]byte, 65535)
	cbuf := make([]byte, 1024)
	for {
		select {
		case <-t.closed:
			return
		default:
		}
		_ = udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
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
			continue
		}
		src := sockaddrToAddrPort(srcSA)
		dst, dstOK := origDstFromCmsg(cbuf[:oobn])
		if !dstOK {
			continue
		}
		if t.cfg.EnforceIsolation && t.inPool(dst.Addr()) {
			continue
		}
		key := src.String() + "|" + dst.String()
		payload := make([]byte, n)
		copy(payload, buf[:n])

		flowsMu.Lock()
		flow, exists := flows[key]
		if !exists {
			f, err := t.openUDPFlow(ctx, src, dst)
			if err != nil {
				flowsMu.Unlock()
				continue
			}
			flow = f
			flows[key] = f
			t.wg.Add(1)
			go t.runUDPFlow(ctx, f, &flowsMu, flows, key)
		}
		flow.lastSeen = time.Now()
		flowsMu.Unlock()

		select {
		case flow.queue <- payload:
		default:
		}
	}
}

// openUDPFlow allocates a per-flow upstream socket and a per-flow
// reply socket. The reply socket is IP_TRANSPARENT-bound to the
// original destination so the client sees responses from the address
// it tried to reach.
func (t *TPROXYListener) openUDPFlow(ctx context.Context, src, dst netip.AddrPort) (*tproxyUDPFlow, error) {
	upstream, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, err
	}
	replyLC := net.ListenConfig{Control: tproxyUDPControl}
	replyAddr := &net.UDPAddr{IP: dst.Addr().AsSlice(), Port: int(dst.Port())}
	reply, err := replyLC.ListenPacket(ctx, "udp", replyAddr.String())
	if err != nil {
		_ = upstream.Close()
		return nil, err
	}
	return &tproxyUDPFlow{
		src:      src,
		dst:      dst,
		queue:    make(chan []byte, 64),
		upstream: upstream,
		reply:    reply,
		done:     make(chan struct{}),
		lastSeen: time.Now(),
	}, nil
}

// runUDPFlow bridges datagrams in both directions for one flow.
// Client packets arrive on flow.queue and go out via flow.upstream;
// upstream replies come back on flow.upstream and go to the client
// via flow.reply (which spoofs the destination address).
func (t *TPROXYListener) runUDPFlow(ctx context.Context, f *tproxyUDPFlow, mu *sync.Mutex, flows map[string]*tproxyUDPFlow, key string) {
	defer t.wg.Done()
	defer func() {
		mu.Lock()
		delete(flows, key)
		mu.Unlock()
		f.closeOne.Do(func() { close(f.done) })
		_ = f.upstream.Close()
		_ = f.reply.Close()
	}()

	clientAddr := &net.UDPAddr{IP: f.src.Addr().AsSlice(), Port: int(f.src.Port())}
	dstAddr := &net.UDPAddr{IP: f.dst.Addr().AsSlice(), Port: int(f.dst.Port())}

	// upstream-to-client goroutine: read from the per-flow upstream
	// socket and write back through the IP_TRANSPARENT reply socket
	// so the client sees the original destination as source.
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		buf := make([]byte, 65535)
		for {
			select {
			case <-f.done:
				return
			default:
			}
			_ = f.upstream.SetReadDeadline(time.Now().Add(t.cfg.UDPIdleTimeout))
			n, _, err := f.upstream.ReadFrom(buf)
			if err != nil {
				return
			}
			if n <= 0 {
				continue
			}
			if _, err := f.reply.WriteTo(buf[:n], clientAddr); err != nil {
				return
			}
		}
	}()

	// client-to-upstream loop: pull from queue, write to upstream.
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.closed:
			return
		case <-f.done:
			return
		case data := <-f.queue:
			if _, err := f.upstream.WriteTo(data, dstAddr); err != nil {
				return
			}
		case <-time.After(t.cfg.UDPIdleTimeout):
			return
		}
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
