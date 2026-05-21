// tproxy-spoof: a tiny transparent TCP proxy that preserves the client's
// source IP on the outbound side.
//
// Standard TPROXY (e.g. mihomo/sing-box) terminates the inbound connection at
// the proxy and opens a fresh outbound from the proxy's IP. That gives the
// split-TCP latency win but the destination sees the proxy's IP.
//
// This program instead:
//   1. accepts the inbound via IP_TRANSPARENT (TPROXY listener)
//   2. learns the original source/destination from the socket's local/remote
//      addresses (TPROXY semantics: getsockname is original dst, getpeername
//      is original src)
//   3. opens a NEW outbound TCP that is also IP_TRANSPARENT-bound to the
//      client's original source IP
//   4. splices the two
//
// Result: the destination sees connections coming from the original client IP
// (e.g. a remote IPv6 that lives behind this proxy's tunnel) while we still
// get the split-TCP slow-start that TPROXY enables.
//
// Run as root (IP_TRANSPARENT + CAP_NET_ADMIN).
package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Constants the unix package may not export on every Go version.
const (
	IP_TRANSPARENT   = 19 // /usr/include/linux/in.h
	IPV6_TRANSPARENT = 75 // /usr/include/linux/in6.h
)

var (
	listenAddr = flag.String("listen", "[::]:22002",
		"TPROXY listen address (dual-stack via [::])")
	logFlows = flag.Bool("v", false, "log each accepted flow")
	noSpoof  = flag.Bool("no_spoof", false,
		"do not bind outbound to client's source IP; use host's default src (relies on POSTROUTING NAT)")
)

func main() {
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	ln, err := listenTransparent(*listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("tproxy-spoof listening on %s", ln.Addr())

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handle(c.(*net.TCPConn))
	}
}

// listenTransparent creates a dual-stack TCP listener with IP_TRANSPARENT.
// With TPROXY rules pointing at this socket, each accepted connection's
// local address is the *original destination* of the redirected flow.
func listenTransparent(addr string) (net.Listener, error) {
	lc := &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var setErr error
			ctlErr := c.Control(func(fd uintptr) {
				f := int(fd)
				_ = unix.SetsockoptInt(f, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				// IP_TRANSPARENT enables TPROXY behaviour. Set on both
				// SOL_IP and IPPROTO_IPV6 for dual-stack sockets — the
				// kernel returns ENOPROTOOPT silently on the irrelevant one.
				if err := unix.SetsockoptInt(f, unix.SOL_IP, IP_TRANSPARENT, 1); err != nil {
					setErr = err
				}
				_ = unix.SetsockoptInt(f, unix.IPPROTO_IPV6, IPV6_TRANSPARENT, 1)
				// Allow v4-mapped on a [::] listener.
				_ = unix.SetsockoptInt(f, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 0)
			})
			if ctlErr != nil {
				return ctlErr
			}
			return setErr
		},
	}
	return lc.Listen(context.Background(), "tcp", addr)
}

func handle(in *net.TCPConn) {
	defer in.Close()

	// TPROXY semantics: the accepted socket's LOCAL address is the original
	// destination the client tried to reach. Remote is the client.
	dst, ok := in.LocalAddr().(*net.TCPAddr)
	if !ok {
		log.Printf("non-tcp local addr: %T", in.LocalAddr())
		return
	}
	src, ok := in.RemoteAddr().(*net.TCPAddr)
	if !ok {
		log.Printf("non-tcp remote addr: %T", in.RemoteAddr())
		return
	}

	if *logFlows {
		log.Printf("flow: %s -> %s", src, dst)
	}

	outConn, err := dialTransparent(src, dst)
	if err != nil {
		if *logFlows {
			log.Printf("dial(%s -> %s): %v", src, dst, err)
		}
		return
	}
	defer outConn.Close()
	out := outConn.(*net.TCPConn)

	// Bidirectional splice. io.Copy is fine; for ~1Gbps it's not a bottleneck.
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(out, in); _ = out.CloseWrite(); done <- struct{}{} }()
	go func() { _, _ = io.Copy(in, out); _ = in.CloseWrite(); done <- struct{}{} }()
	<-done
	<-done
}

// dialTransparent opens an outbound TCP connection that pretends to come from
// `src.IP`. The kernel must allow this: IP_TRANSPARENT lets us bind to any
// address. Local routing on the host has to send replies back here (i.e. the
// host must own the route to `src.IP` somehow, e.g. via NDP proxy + a route
// over a tunnel netdev pointing at us).
func dialTransparent(src, dst *net.TCPAddr) (net.Conn, error) {
	network := "tcp6"
	if v4 := src.IP.To4(); v4 != nil && dst.IP.To4() != nil {
		network = "tcp4"
	}

	d := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var setErr error
			ctlErr := c.Control(func(fd uintptr) {
				f := int(fd)
				if !*noSpoof {
					if err := unix.SetsockoptInt(f, unix.SOL_IP, IP_TRANSPARENT, 1); err != nil {
						setErr = err
					}
					_ = unix.SetsockoptInt(f, unix.IPPROTO_IPV6, IPV6_TRANSPARENT, 1)
				}
			})
			if ctlErr != nil {
				return ctlErr
			}
			return setErr
		},
	}
	if !*noSpoof {
		// Bind locally to the original client's source IP, ephemeral port.
		d.LocalAddr = &net.TCPAddr{IP: src.IP, Port: 0}
	}
	return d.DialContext(context.Background(), network, dst.String())
}

// unused but useful diagnostic
var _ = os.Stderr
