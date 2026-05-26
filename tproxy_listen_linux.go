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
	"unsafe"

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
// SO_REUSEADDR so restarts don't TIME_WAIT-block, and TCP_FASTOPEN
// so the listener accepts SYN+data on the first packet — sing-box
// also enables this and it saves one RTT on every new connection.
// Backlog 256 mirrors the kernel default for TFO queue depth.
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
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN, 256)
	})
	if err != nil {
		return err
	}
	return setErr
}

// tproxyUDPControl mirrors tproxyTCPControl for UDP and additionally
// asks the kernel to deliver the original-destination + TOS/Class
// cmsgs on each recvmmsg. The TOS/Class cmsg lets us preserve DSCP
// from the redirected packet onto the upstream-side send so QoS
// markings survive the forward (mihomo does this; sing-box doesn't).
// NO explicit SO_RCVBUF: same reason as TCP — kernel autotunes up to
// net.core.rmem_max, an explicit value caps the autotune ceiling.
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
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTOS, 1)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVTCLASS, 1)
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	})
	if err != nil {
		return err
	}
	return setErr
}

// tuneTCP mirrors what sing-box does on a forwarded TCP socket:
// TCP_NODELAY (default in Go anyway), keepalive, and BBR congestion
// control. NO explicit SO_SNDBUF / SO_RCVBUF — setting those caps
// Linux's TCP auto-tuning at the requested value instead of letting
// it grow to net.core.{r,w}mem_max (which on a modern host is
// 32-64 MiB). NO TCP_USER_TIMEOUT — sing-box doesn't set it and
// killing connections at 30s of no-ACK can prematurely drop long
// idle proxied flows.
func tuneTCP(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetNoDelay(true)
	_ = tc.SetKeepAlive(true)
	_ = tc.SetKeepAlivePeriod(30 * time.Second)
	_ = applyBBR(c)
}

// tunedTCPDialer mirrors sing-box's outbound dial: KeepAlive on, BBR
// applied via Control so cwnd ramps under BBR from the first SYN,
// and TCP_FASTOPEN_CONNECT so the SYN carries the first request bytes
// (saves one RTT on connection setup; ignored by the kernel if the
// destination doesn't support TFO).
func tunedTCPDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if bbrAvailable() {
					_ = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, "bbr")
				}
				_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN_CONNECT, 1)
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
	lastDSCP     byte         // last DSCP byte applied to upstream
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

// udpAcceptLoop reads UDP packets from the TPROXY listener in
// batches via recvmmsg(2) and fans them out to per-flow connected
// upstream sockets. Batched receive amortises the syscall overhead
// across up to udpBatchSize packets per call; sing-box uses the
// same trick. We don't batch the upstream send because each packet
// in a batch may belong to a different flow (different connected
// socket), so per-packet Write is the correct shape after fanout.
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

	batch := newUDPRxBatch(udpBatchSize)
	for {
		select {
		case <-t.closed:
			return
		default:
		}
		_ = udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))

		batch.arm()
		var n int
		var errno syscall.Errno
		cerr := sc.Read(func(fd uintptr) bool {
			n, errno = recvmmsg(int(fd), batch.msgs, 0)
			return !errors.Is(errno, unix.EAGAIN) && !errors.Is(errno, unix.EWOULDBLOCK)
		})
		if cerr != nil {
			select {
			case <-t.closed:
				return
			default:
			}
			if errors.Is(cerr, net.ErrClosed) {
				return
			}
			var ne net.Error
			if errors.As(cerr, &ne) && ne.Timeout() {
				continue
			}
			continue
		}
		if errno != 0 {
			if errno == unix.EAGAIN || errno == unix.EWOULDBLOCK {
				continue
			}
			continue
		}
		for i := 0; i < n; i++ {
			msg := &batch.msgs[i]
			payloadLen := int(msg.Len)
			if payloadLen <= 0 {
				continue
			}
			src := rawSockaddrToAddrPort(&batch.names[i])
			dst, dscp, dstOK := parsePerPacketCmsg(batch.cbufs[i][:msg.Hdr.Controllen])
			if !dstOK {
				continue
			}
			if t.cfg.EnforceIsolation && t.inPool(dst.Addr()) {
				continue
			}
			key := src.String() + "|" + dst.String()

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
				go t.runUDPReplyPump(ctx, f, &flowsMu, flows, key)
			}
			flow.bump()
			flowsMu.Unlock()

			// DSCP propagation: if the inbound packet carried a non-
			// zero DSCP marking and it differs from what the upstream
			// socket currently has, update it before write. Cached on
			// the flow so we don't setsockopt every packet.
			if dscp != 0 && dscp != flow.lastDSCP {
				applyDSCP(flow.upstream, dst.Addr().Is6(), dscp)
				flow.lastDSCP = dscp
			}
			_, _ = flow.upstream.Write(batch.bufs[i][:payloadLen])
		}
	}
}

// parsePerPacketCmsg extracts both the original-destination address
// and the DSCP byte (IP_TOS / IPV6_TCLASS) from a single packet's
// control-message buffer. Reuses the cmsg walker; one pass.
func parsePerPacketCmsg(cbuf []byte) (dst netip.AddrPort, dscp byte, ok bool) {
	msgs, err := unix.ParseSocketControlMessage(cbuf)
	if err != nil {
		return netip.AddrPort{}, 0, false
	}
	for _, m := range msgs {
		switch {
		case m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_ORIGDSTADDR && len(m.Data) >= 8:
			port := binary.BigEndian.Uint16(m.Data[2:4])
			var v4 [4]byte
			copy(v4[:], m.Data[4:8])
			dst = netip.AddrPortFrom(netip.AddrFrom4(v4), port)
			ok = true
		case m.Header.Level == unix.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_ORIGDSTADDR && len(m.Data) >= 24:
			port := binary.BigEndian.Uint16(m.Data[2:4])
			var v6 [16]byte
			copy(v6[:], m.Data[8:24])
			dst = netip.AddrPortFrom(netip.AddrFrom16(v6), port)
			ok = true
		case m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_TOS && len(m.Data) >= 1:
			dscp = m.Data[0]
		case m.Header.Level == unix.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_TCLASS && len(m.Data) >= 4:
			// IPV6_TCLASS comes as a 4-byte int; the TOS byte is the
			// low octet on little-endian kernels.
			dscp = m.Data[0]
		}
	}
	return
}

// rawSockaddrToAddrPort converts the kernel's RawSockaddrAny (the
// name field of a Msghdr) into a netip.AddrPort. Handles both v4 and
// v4-mapped-v6 (since our TPROXY socket is dual-stack and v4 packets
// arrive with ::ffff:a.b.c.d sockaddrs).
func rawSockaddrToAddrPort(sa *unix.RawSockaddrAny) netip.AddrPort {
	switch sa.Addr.Family {
	case unix.AF_INET:
		p := (*unix.RawSockaddrInet4)(unsafe.Pointer(sa))
		return netip.AddrPortFrom(netip.AddrFrom4(p.Addr), uint16(p.Port>>8|p.Port<<8))
	case unix.AF_INET6:
		p := (*unix.RawSockaddrInet6)(unsafe.Pointer(sa))
		addr := netip.AddrFrom16(p.Addr)
		if v4 := addr.As4(); addr.Is4In6() {
			addr = netip.AddrFrom4(v4)
		}
		return netip.AddrPortFrom(addr, uint16(p.Port>>8|p.Port<<8))
	}
	return netip.AddrPort{}
}

// applyDSCP sets IP_TOS (v4) or IPV6_TCLASS (v6) on the given UDP
// conn, preserving the DSCP marking from an inbound packet onto
// subsequent outbound packets on this socket. Caller should cache
// the value and avoid setsockopt'ing the same byte twice.
func applyDSCP(conn *net.UDPConn, isV6 bool, dscp byte) {
	sc, err := conn.SyscallConn()
	if err != nil {
		return
	}
	_ = sc.Control(func(fd uintptr) {
		if isV6 {
			_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_TCLASS, int(dscp))
		} else {
			_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS, int(dscp))
		}
	})
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

