package packethose

import "io"

// PacketIO is the interface lanes use to ingest and emit raw IP packets. One
// instance per lane: lanes do not multiplex across a shared PacketIO.
//
// Implementations:
//   - kernelTUN (this package): /dev/net/tun queue, optionally with
//     IFF_VNET_HDR prepending a 10-byte virtio_net_hdr.
//   - Caller-supplied (e.g. a userspace netstack endpoint): an embedding
//     program can wire in a gVisor-backed PacketIO to avoid an OS TUN device.
//
// Read returns one complete packet (or one vnet_hdr+packet super-frame when
// VnetHdr() is true). Write delivers one complete packet to the network
// stack. Both follow standard io conventions: short reads/writes are not
// expected for L3 datagram boundaries.
type PacketIO interface {
	io.ReadWriteCloser

	// VnetHdr reports whether reads and writes carry a 10-byte
	// virtio_net_hdr prefix in front of the L3 payload. Both peers must
	// agree out-of-band; mismatched modes produce garbage at the receiver.
	VnetHdr() bool
}

// usoController is implemented by PacketIO backends that can toggle UDP
// segmentation offload (the kernel TUN). The supervisor type-asserts for it
// and enables USO once the handshake confirms the peer supports it too.
// Backends without it (userspace netstack, the multi-client shared-TUN
// wrapper) simply run TSO-only.
type usoController interface {
	USOSupported() bool
	SetUSO(enable bool) error
}

// localUSO reports whether a set of lane queues can do UDP segmentation
// offload (all must agree; the queues are the same device).
func localUSO(queues []PacketIO) bool {
	for _, q := range queues {
		u, ok := q.(usoController)
		if !ok || !u.USOSupported() {
			return false
		}
	}
	return len(queues) > 0
}
