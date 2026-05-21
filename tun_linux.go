package main

import (
	"bytes"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	ifNamSize     = 16
	iffTun        = 0x0001
	iffNoPI       = 0x1000
	iffMultiQueue = 0x0100
	iffVnetHdr    = 0x4000
)

type ifreq struct {
	Name  [ifNamSize]byte
	Flags uint16
	_     [22]byte
}

func openTunQueue(name string, multiQueue bool) (int, string, error) {
	return openTunQueueOpts(name, multiQueue, false)
}

// openTunQueueOpts opens a TUN queue, optionally with IFF_VNET_HDR. When vnetHdr
// is true the kernel will prepend a virtio_net_hdr to every TUN read and expect
// the same prefix on every TUN write, enabling GRO on reads (super-packets) and
// GSO on writes (auto-segmentation).
func openTunQueueOpts(name string, multiQueue, vnetHdr bool) (int, string, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", fmt.Errorf("open /dev/net/tun: %w", err)
	}
	var req ifreq
	copy(req.Name[:], name)
	req.Flags = iffTun | iffNoPI
	if multiQueue {
		req.Flags |= iffMultiQueue
	}
	if vnetHdr {
		req.Flags |= iffVnetHdr
	}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		unix.Close(fd)
		return -1, "", fmt.Errorf("TUNSETIFF: %w", errno)
	}
	if vnetHdr {
		// Pin the header size to 10 (the legacy virtio_net_hdr layout). The
		// kernel default is already 10, but be explicit so we never desync
		// with a kernel that ships a different default.
		sz := uint32(virtioNetHdrLen)
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETVNETHDRSZ), uintptr(unsafe.Pointer(&sz)))
		if errno != 0 {
			unix.Close(fd)
			return -1, "", fmt.Errorf("TUNSETVNETHDRSZ: %w", errno)
		}
		// Ask the kernel to coalesce TCP segments on TUN reads (GRO) and to
		// segment large TCP super-packets we write back (GSO). We enable v4
		// and v6 TCP segmentation plus checksum offload. Without this the
		// IFF_VNET_HDR flag is still honored but the kernel will only ever
		// return single packets - the GRO coalescing path needs the offload
		// hint to engage.
		off := uint32(unix.TUN_F_CSUM | unix.TUN_F_TSO4 | unix.TUN_F_TSO6)
		_, _, errno = unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETOFFLOAD), uintptr(off))
		if errno != 0 {
			unix.Close(fd)
			return -1, "", fmt.Errorf("TUNSETOFFLOAD: %w", errno)
		}
	}
	return fd, string(bytes.TrimRight(req.Name[:], "\x00")), nil
}
