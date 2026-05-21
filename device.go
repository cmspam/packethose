// Cross-platform TUN device scaffold.
//
// This file is a design sketch. The next agent should:
//
//   1. Plumb this interface through lane.go (replace the bare `tunFd int`
//      with a `Device` parameter).
//   2. Provide a Linux implementation in `device_linux.go` that wraps the
//      existing tun_linux.go file's openTunQueueOpts behaviour, including
//      the IFF_VNET_HDR + TUNSETOFFLOAD path.
//   3. Provide a macOS implementation in `device_darwin.go` using
//      `unix.AF_SYSTEM` + `SYSPROTO_CONTROL` + `UTUN_CONTROL_NAME`. macOS
//      utun packets are prefixed by a 4-byte big-endian protocol family
//      (AF_INET = 2, AF_INET6 = 30); strip on Read, prepend on Write.
//   4. Provide a Windows implementation later via Wintun
//      (https://www.wintun.net/). WireGuard-Go's `tun/tun_windows.go`
//      is a clean reference.
//
// Today the Go code uses raw fds (`unix.Read`/`unix.Write` directly), so
// the abstraction below is unimplemented. Migrating the data path is a
// modest refactor: lane.go's tunToSock and sockToTun become
// device.Read(buf) and device.Write(buf), respectively.
//
// The interface intentionally exposes "batch" forms so VNET_HDR-aware
// backends can return multiple packets per syscall. Non-batching backends
// should return 1 packet per ReadBatch call (just slot it into the first
// element).

package main

// Device abstracts a TUN-like virtual network interface.
//
// Implementations:
//   Linux: /dev/net/tun ioctl (with optional IFF_VNET_HDR)
//   macOS: utun via PF_SYSTEM + SYSPROTO_CONTROL
//   Windows: Wintun via wintun.dll
//   FreeBSD: /dev/tun (simpler, no MULTI_QUEUE)
type Device interface {
	// Name returns the kernel-assigned interface name (e.g., "tun0").
	Name() string

	// MTU returns the inner MTU, in bytes.
	MTU() int

	// Read receives a single raw IP packet into buf. Returns the number
	// of bytes written. With VNET_HDR-capable backends, the first 10
	// bytes of buf are the virtio_net_hdr; payload follows.
	Read(buf []byte) (int, error)

	// Write delivers a raw IP packet to the kernel. With VNET_HDR-capable
	// backends, buf must include the 10-byte virtio_net_hdr prefix.
	Write(buf []byte) (int, error)

	// VnetHdr reports whether this device prepends/expects a 10-byte
	// virtio_net_hdr on every Read/Write.
	VnetHdr() bool

	// Close releases the device.
	Close() error
}

// NewDevice opens a TUN device with the given name. Implementations may
// honor or ignore the requested features depending on platform support.
//
// Currently a stub. The Linux file descriptor based path in lane.go is the
// production code; this scaffold is for future cross-platform work.
type DeviceOpts struct {
	Name       string
	MTU        int
	MultiQueue bool
	VnetHdr    bool
}
