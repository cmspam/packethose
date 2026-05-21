//go:build linux

package packethose

import (
	"bytes"
	"errors"
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

	virtioNetHdrLen = 10
)

type ifreq struct {
	Name  [ifNamSize]byte
	Flags uint16
	_     [22]byte
}

// kernelTUN is a Linux /dev/net/tun queue. It is one PacketIO per queue;
// open multiple via OpenKernelTUN to feed multi-lane setups.
type kernelTUN struct {
	fd      int
	vnetHdr bool
}

func (k *kernelTUN) Read(p []byte) (int, error) {
	for {
		n, err := unix.Read(k.fd, p)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return n, err
	}
}

func (k *kernelTUN) Write(p []byte) (int, error)  { return unix.Write(k.fd, p) }
func (k *kernelTUN) Close() error                 { return unix.Close(k.fd) }
func (k *kernelTUN) VnetHdr() bool                { return k.vnetHdr }

// OpenKernelTUN opens `queues` queues on the named multi-queue TUN device.
// If the device does not exist, the kernel creates it. The returned slice has
// exactly `queues` PacketIO entries; one per lane.
//
// vnetHdr enables IFF_VNET_HDR (size 10), TUNSETOFFLOAD with CSUM+TSO4+TSO6,
// and produces super-packets via kernel GRO that ride the lane verbatim.
//
// Returns the negotiated interface name (which may differ from `name` if the
// kernel renumbered it) and the queue PacketIOs.
func OpenKernelTUN(name string, queues int, vnetHdr bool) ([]PacketIO, string, error) {
	if queues < 1 {
		return nil, "", fmt.Errorf("queues must be >= 1")
	}
	out := make([]PacketIO, 0, queues)
	var ifname string
	for i := 0; i < queues; i++ {
		fd, nm, err := openTunQueue(name, queues > 1, vnetHdr)
		if err != nil {
			for _, p := range out {
				_ = p.Close()
			}
			return nil, "", fmt.Errorf("open queue %d: %w", i, err)
		}
		if ifname == "" {
			ifname = nm
		}
		out = append(out, &kernelTUN{fd: fd, vnetHdr: vnetHdr})
	}
	return out, ifname, nil
}

func openTunQueue(name string, multiQueue, vnetHdr bool) (int, string, error) {
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
		sz := uint32(virtioNetHdrLen)
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETVNETHDRSZ), uintptr(unsafe.Pointer(&sz)))
		if errno != 0 {
			unix.Close(fd)
			return -1, "", fmt.Errorf("TUNSETVNETHDRSZ: %w", errno)
		}
		// Enable TCP segmentation + checksum offload so the kernel coalesces
		// inbound segments (GRO) and re-segments outbound super-packets (GSO).
		off := uint32(unix.TUN_F_CSUM | unix.TUN_F_TSO4 | unix.TUN_F_TSO6)
		_, _, errno = unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETOFFLOAD), uintptr(off))
		if errno != 0 {
			unix.Close(fd)
			return -1, "", fmt.Errorf("TUNSETOFFLOAD: %w", errno)
		}
	}
	return fd, string(bytes.TrimRight(req.Name[:], "\x00")), nil
}
