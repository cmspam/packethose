// Package netstack provides a userspace IP stack (backed by gVisor) that
// can drive a packethose tunnel without requiring a kernel TUN device.
//
// Typical use:
//
//	st, err := netstack.NewStack(1500)
//	st.AddAddress(netip.MustParsePrefix("10.66.0.2/24"))
//	pio := st.PacketIO()                  // pass into ClientConfig.Queues
//	conn, err := st.DialContext(ctx, ...) // dial through the tunnel
//
// One Stack per tunnel; for a multi-queue setup, replicate the LinkEndpoint
// across multiple Stacks or use a single-queue ClientConfig.Lanes=1.
package netstack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv6"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/icmp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
)

const nicID tcpip.NICID = 1

// Stack is a userspace IP stack bound to a single virtual NIC. It implements
// packethose.PacketIO via its endpoint, and exposes Dial/ListenPacket on the
// stack's TCP/UDP/ICMP transports.
type Stack struct {
	s   *stack.Stack
	ep  *endpoint
	mtu uint32
}

// NewStack creates a stack with TCP, UDP, ICMPv4 and ICMPv6 transport
// protocols and IPv4/IPv6 network protocols enabled. The MTU caps the size
// of packets the stack will emit; match it to the tunnel's effective MTU.
func NewStack(mtu uint32) (*Stack, error) {
	ep := newEndpoint(mtu)
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("CreateNIC: %v", err)
	}
	// Promiscuous so the stack accepts packets destined to addresses we have
	// not yet added (e.g. inbound ICMP echo to a non-bound IP).
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("SetPromiscuousMode: %v", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("SetSpoofing: %v", err)
	}
	// Default routes for v4 and v6 through the NIC.
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})
	return &Stack{s: s, ep: ep, mtu: mtu}, nil
}

// AddAddress assigns an IP address (with prefix) to the stack's NIC. Multiple
// addresses can coexist.
func (st *Stack) AddAddress(p netip.Prefix) error {
	var protoNum tcpip.NetworkProtocolNumber
	switch {
	case p.Addr().Is4():
		protoNum = ipv4.ProtocolNumber
	case p.Addr().Is6():
		protoNum = ipv6.ProtocolNumber
	default:
		return errors.New("address must be IPv4 or IPv6")
	}
	addr := tcpip.AddrFromSlice(p.Addr().AsSlice())
	proto := tcpip.ProtocolAddress{
		Protocol:          protoNum,
		AddressWithPrefix: addr.WithPrefix(),
	}
	if err := st.s.AddProtocolAddress(nicID, proto, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("AddProtocolAddress: %v", err)
	}
	return nil
}

// PacketIO returns the link-side I/O bridge. Hand this to a packethose
// ClientConfig.Queues or ServerConfig.Queues entry (one entry, single lane).
func (st *Stack) PacketIO() *Endpoint { return st.ep.public() }

// DialContext opens a connection through the stack to addr. network is "tcp",
// "tcp4", "tcp6", "udp", "udp4", or "udp6".
func (st *Stack) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	addrPort, err := netip.ParseAddrPort(net.JoinHostPort(host, port))
	if err != nil {
		ipa, ferr := netip.ParseAddr(host)
		if ferr != nil {
			return nil, err
		}
		var p uint64
		fmt.Sscanf(port, "%d", &p)
		addrPort = netip.AddrPortFrom(ipa, uint16(p))
	}
	var protoNum tcpip.NetworkProtocolNumber
	if addrPort.Addr().Is4() {
		protoNum = ipv4.ProtocolNumber
	} else {
		protoNum = ipv6.ProtocolNumber
	}
	full := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(addrPort.Addr().AsSlice()),
		Port: addrPort.Port(),
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
		return gonet.DialContextTCP(ctx, st.s, full, protoNum)
	case "udp", "udp4", "udp6":
		// gonet.DialUDP is not context-aware; ctx cancel falls back to
		// later read deadlines.
		return gonet.DialUDP(st.s, nil, &full, protoNum)
	}
	return nil, fmt.Errorf("unsupported network %q", network)
}

// ListenPacket binds a UDP socket on the stack at addr. addr may be empty for
// an ephemeral bind.
func (st *Stack) ListenPacket(network, addr string) (net.PacketConn, error) {
	var full tcpip.FullAddress
	full.NIC = nicID
	if addr != "" {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ipa, err := netip.ParseAddr(host)
		if err != nil {
			return nil, err
		}
		var p uint64
		fmt.Sscanf(port, "%d", &p)
		full.Addr = tcpip.AddrFromSlice(ipa.AsSlice())
		full.Port = uint16(p)
	}
	var protoNum tcpip.NetworkProtocolNumber
	if full.Addr.Len() == 4 {
		protoNum = ipv4.ProtocolNumber
	} else {
		protoNum = ipv6.ProtocolNumber
	}
	return gonet.DialUDP(st.s, &full, nil, protoNum)
}

// ListenTCP binds a TCP listening socket on the stack.
func (st *Stack) ListenTCP(addr string) (net.Listener, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ipa, err := netip.ParseAddr(host)
	if err != nil {
		return nil, err
	}
	var p uint64
	fmt.Sscanf(port, "%d", &p)
	var protoNum tcpip.NetworkProtocolNumber
	if ipa.Is4() {
		protoNum = ipv4.ProtocolNumber
	} else {
		protoNum = ipv6.ProtocolNumber
	}
	return gonet.ListenTCP(st.s, tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(ipa.AsSlice()),
		Port: uint16(p),
	}, protoNum)
}

// Close tears the stack down.
func (st *Stack) Close() error {
	st.s.Close()
	st.s.Wait()
	st.ep.Close()
	return nil
}

// ---- LinkEndpoint ----

// endpoint is the gVisor LinkEndpoint glue. It also exposes a PacketIO via
// Endpoint (the public-facing wrapper) for the packethose lane to consume.
type endpoint struct {
	mtu uint32

	// outQueue holds packets the gVisor stack wants to emit. packethose
	// pulls them via Endpoint.Read.
	outQueue chan []byte

	dispatcherMu sync.RWMutex
	dispatcher   stack.NetworkDispatcher

	closed  atomic.Bool
	onClose func()
}

func newEndpoint(mtu uint32) *endpoint {
	return &endpoint{
		mtu:      mtu,
		outQueue: make(chan []byte, 1024),
	}
}

func (e *endpoint) public() *Endpoint { return &Endpoint{e: e} }

// MTU implements stack.LinkEndpoint.
func (e *endpoint) MTU() uint32 { return e.mtu }

// SetMTU implements stack.LinkEndpoint.
func (e *endpoint) SetMTU(mtu uint32) { e.mtu = mtu }

// MaxHeaderLength implements stack.LinkEndpoint. No L2 header for raw IP.
func (e *endpoint) MaxHeaderLength() uint16 { return 0 }

// LinkAddress implements stack.LinkEndpoint. Raw IP has no link address.
func (e *endpoint) LinkAddress() tcpip.LinkAddress { return "" }

// SetLinkAddress implements stack.LinkEndpoint. No-op for raw IP.
func (e *endpoint) SetLinkAddress(addr tcpip.LinkAddress) {}

// Capabilities implements stack.LinkEndpoint.
func (e *endpoint) Capabilities() stack.LinkEndpointCapabilities { return 0 }

// Attach implements stack.LinkEndpoint. Called by gVisor stack on NIC create.
func (e *endpoint) Attach(d stack.NetworkDispatcher) {
	e.dispatcherMu.Lock()
	e.dispatcher = d
	e.dispatcherMu.Unlock()
}

// IsAttached implements stack.LinkEndpoint.
func (e *endpoint) IsAttached() bool {
	e.dispatcherMu.RLock()
	defer e.dispatcherMu.RUnlock()
	return e.dispatcher != nil
}

// Wait implements stack.LinkEndpoint.
func (e *endpoint) Wait() {}

// ARPHardwareType implements stack.LinkEndpoint.
func (e *endpoint) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }

// AddHeader implements stack.LinkEndpoint. No L2 to add.
func (e *endpoint) AddHeader(*stack.PacketBuffer) {}

// ParseHeader implements stack.LinkEndpoint. No L2 to parse.
func (e *endpoint) ParseHeader(*stack.PacketBuffer) bool { return true }

// WritePackets implements stack.LinkEndpoint: enqueue packets for the lane.
func (e *endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	written := 0
	for _, pkt := range pkts.AsSlice() {
		if e.closed.Load() {
			return written, &tcpip.ErrClosedForSend{}
		}
		buf := pkt.ToView().AsSlice()
		// Copy because the PacketBuffer's underlying storage may be
		// recycled after this call returns.
		out := make([]byte, len(buf))
		copy(out, buf)
		select {
		case e.outQueue <- out:
			written++
		default:
			// Queue full: drop. Matches ipip behavior under congestion.
		}
	}
	return written, nil
}

// inject delivers a packet from the lane into the stack.
func (e *endpoint) inject(pkt []byte) {
	e.dispatcherMu.RLock()
	d := e.dispatcher
	e.dispatcherMu.RUnlock()
	if d == nil || e.closed.Load() {
		return
	}
	// Determine protocol from first nibble.
	if len(pkt) < 1 {
		return
	}
	var proto tcpip.NetworkProtocolNumber
	switch pkt[0] >> 4 {
	case 4:
		proto = ipv4.ProtocolNumber
	case 6:
		proto = ipv6.ProtocolNumber
	default:
		return
	}
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(pkt),
	})
	d.DeliverNetworkPacket(proto, pb)
	pb.DecRef()
}

// Close implements stack.LinkEndpoint (and shuts the queue).
func (e *endpoint) Close() {
	if e.closed.Swap(true) {
		return
	}
	close(e.outQueue)
	if a := e.onClose; a != nil {
		a()
	}
}

// SetOnCloseAction implements stack.LinkEndpoint.
func (e *endpoint) SetOnCloseAction(action func()) {
	e.onClose = action
}

// ---- Public Endpoint wrapper (PacketIO) ----

// Endpoint is the link-side handle the packethose lane consumes.
type Endpoint struct {
	e *endpoint
}

// Read returns the next outbound packet emitted by the stack. Blocks.
func (p *Endpoint) Read(buf []byte) (int, error) {
	pkt, ok := <-p.e.outQueue
	if !ok {
		return 0, net.ErrClosed
	}
	n := copy(buf, pkt)
	return n, nil
}

// Write injects an inbound packet into the stack.
func (p *Endpoint) Write(buf []byte) (int, error) {
	if p.e.closed.Load() {
		return 0, net.ErrClosed
	}
	pkt := make([]byte, len(buf))
	copy(pkt, buf)
	p.e.inject(pkt)
	return len(buf), nil
}

// Close terminates the endpoint.
func (p *Endpoint) Close() error {
	p.e.Close()
	return nil
}

// VnetHdr reports whether the link carries a virtio_net_hdr prefix. Always
// false for the userspace netstack — it deals in raw L3 packets.
func (p *Endpoint) VnetHdr() bool { return false }

// SetReadDeadline implements net.Conn-like semantics for tests. Unused at
// runtime but stays compatible with future Conn-style consumers.
func (p *Endpoint) SetReadDeadline(t time.Time) error { return nil }

// Compile-time check: *Endpoint satisfies packethose.PacketIO.
var _ packetIOInterface = (*Endpoint)(nil)

// packetIOInterface mirrors packethose.PacketIO without importing it, to avoid
// a tight coupling. If the parent package's interface evolves, update here.
type packetIOInterface interface {
	Read(p []byte) (n int, err error)
	Write(p []byte) (n int, err error)
	Close() error
	VnetHdr() bool
}
