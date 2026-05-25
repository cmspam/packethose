//go:build linux

package packethose

import (
	"errors"
	"io"
	"net/netip"
)

// sessionPIO is the per-lane PacketIO used in shared-TUN mode.
// Reads pull packets the shared-TUN readers dispatched to this
// session's outbound channel (packets the kernel wrote to phose0
// destined for this client). Writes go to one of the shared TUN
// queues so the kernel sees inbound-from-tunnel traffic on phose0
// and routes it normally.
//
// Multiple lanes for the same session share the outbound channel
// for reads; whichever lane's Read fires first claims the packet.
// Each lane is assigned a distinct shared queue for writes so the
// kernel processes them in parallel.
type sessionPIO struct {
	sess     *session
	tunWrite PacketIO
	vnetHdr  bool
}

func newSessionPIO(s *session, w PacketIO, vnetHdr bool) *sessionPIO {
	return &sessionPIO{sess: s, tunWrite: w, vnetHdr: vnetHdr}
}

// Read returns one packet (vnet_hdr-prefixed when vnetHdr is true)
// or io.EOF when the session is torn down.
func (s *sessionPIO) Read(p []byte) (int, error) {
	select {
	case <-s.sess.closed:
		return 0, io.EOF
	case pkt, ok := <-s.sess.outbound:
		if !ok {
			return 0, io.EOF
		}
		if len(pkt) > len(p) {
			return 0, errShortBuffer
		}
		return copy(p, pkt), nil
	}
}

// Write delivers a packet (vnet_hdr-prefixed when vnetHdr is true)
// to the shared TUN queue assigned to this lane.
func (s *sessionPIO) Write(p []byte) (int, error) {
	return s.tunWrite.Write(p)
}

// Close is a no-op: the shared TUN queues are owned by the server,
// not by individual lanes. The lane's outer TCP connection's own
// Close handles teardown.
func (s *sessionPIO) Close() error { return nil }

// VnetHdr matches the shared TUN's mode so lane.go's I/O loops
// allocate the right buffer prefix.
func (s *sessionPIO) VnetHdr() bool { return s.vnetHdr }

var errShortBuffer = errors.New("packethose: session pio: short read buffer")

// innerDst returns the destination IP from a raw L3 packet
// (optionally preceded by a 10-byte virtio_net_hdr). Used by the
// shared TUN's per-queue reader to route packets to the right
// session.
func innerDst(pkt []byte, vnetHdr bool) (netip.Addr, bool) {
	if vnetHdr {
		if len(pkt) < virtioNetHdrLen {
			return netip.Addr{}, false
		}
		pkt = pkt[virtioNetHdrLen:]
	}
	if len(pkt) < 1 {
		return netip.Addr{}, false
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return netip.Addr{}, false
		}
		var a [4]byte
		copy(a[:], pkt[16:20])
		return netip.AddrFrom4(a), true
	case 6:
		if len(pkt) < 40 {
			return netip.Addr{}, false
		}
		var a [16]byte
		copy(a[:], pkt[24:40])
		return netip.AddrFrom16(a), true
	}
	return netip.Addr{}, false
}
