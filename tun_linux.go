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

	// tunOffloadBase is the always-on offload set: checksum + TCP
	// segmentation, so the kernel GRO-coalesces inbound TCP and re-segments
	// outbound TCP super-packets.
	tunOffloadBase = unix.TUN_F_CSUM | unix.TUN_F_TSO4 | unix.TUN_F_TSO6
	// TUN_F_USO4/USO6 add UDP segmentation offload (Linux >= 6.2). With
	// these the kernel coalesces same-flow UDP datagrams into GSO
	// super-packets on read and re-segments on write, giving UDP the same
	// batching TCP gets. Not in older x/sys/unix, so defined here.
	tunFUSO4 = 0x20
	tunFUSO6 = 0x40
)

type ifreq struct {
	Name  [ifNamSize]byte
	Flags uint16
	_     [22]byte
}

// kernelTUN is a Linux /dev/net/tun queue. It is one PacketIO per queue;
// open multiple via OpenKernelTUN to feed multi-lane setups.
type kernelTUN struct {
	fd       int
	vnetHdr  bool
	usoOK    bool // kernel accepted UDP segmentation offload on this queue
	nonblock bool // fd switched to non-blocking for batched reads
}

// ReadBatch blocks for at least one packet, then drains any further
// packets the kernel already has queued (up to len(bufs)) without
// blocking. lens[i] receives the length of packet i. It lets the data
// path coalesce a burst of small datagrams into one tunnel frame,
// amortizing the per-packet crypto and socket cost that makes UDP
// pps-bound. The queue fd is switched to non-blocking on first use; this
// queue must be owned by a single reader (true for per-lane kernel TUNs).
func (k *kernelTUN) ReadBatch(bufs [][]byte, lens []int) (int, error) {
	if !k.nonblock {
		if err := unix.SetNonblock(k.fd, true); err != nil {
			return 0, err
		}
		k.nonblock = true
	}
	pfd := []unix.PollFd{{Fd: int32(k.fd), Events: unix.POLLIN}}
	for { // block until the first packet is available
		n, err := unix.Read(k.fd, bufs[0])
		if err == nil {
			lens[0] = n
			break
		}
		if errors.Is(err, unix.EAGAIN) {
			if _, perr := unix.Poll(pfd, -1); perr != nil && !errors.Is(perr, unix.EINTR) {
				return 0, perr
			}
			continue
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return 0, err
	}
	count := 1
	for count < len(bufs) { // drain whatever else is already queued
		n, err := unix.Read(k.fd, bufs[count])
		if err != nil { // EAGAIN (nothing more) or a real error: stop draining
			break
		}
		lens[count] = n
		count++
	}
	return count, nil
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

func (k *kernelTUN) Write(p []byte) (int, error) { return unix.Write(k.fd, p) }
func (k *kernelTUN) Close() error                { return unix.Close(k.fd) }
func (k *kernelTUN) VnetHdr() bool               { return k.vnetHdr }

// USOSupported reports whether this queue's kernel accepted UDP
// segmentation offload (requires vnet_hdr and Linux >= ~6.2).
func (k *kernelTUN) USOSupported() bool { return k.usoOK }

// SetUSO toggles UDP segmentation offload on this queue. Enabling is only
// valid after the handshake confirms the peer also supports USO, since a
// USO super-packet must be segmentable on the receiving TUN.
func (k *kernelTUN) SetUSO(enable bool) error {
	if !k.vnetHdr {
		if enable {
			return errors.New("USO requires vnet_hdr")
		}
		return nil
	}
	if enable && !k.usoOK {
		return errors.New("USO not supported by this kernel")
	}
	return tunSetOffload(k.fd, enable)
}

// tunSetOffload sets the TUN offload mask: always checksum + TSO, plus USO
// when uso is true.
func tunSetOffload(fd int, uso bool) error {
	off := uint32(tunOffloadBase)
	if uso {
		off |= tunFUSO4 | tunFUSO6
	}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETOFFLOAD), uintptr(off))
	if errno != 0 {
		return errno
	}
	return nil
}

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
		fd, nm, uso, err := openTunQueue(name, queues > 1, vnetHdr)
		if err != nil {
			for _, p := range out {
				_ = p.Close()
			}
			return nil, "", fmt.Errorf("open queue %d: %w", i, err)
		}
		if ifname == "" {
			ifname = nm
		}
		out = append(out, &kernelTUN{fd: fd, vnetHdr: vnetHdr, usoOK: uso})
	}
	return out, ifname, nil
}

func openTunQueue(name string, multiQueue, vnetHdr bool) (int, string, bool, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", false, fmt.Errorf("open /dev/net/tun: %w", err)
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
		return -1, "", false, fmt.Errorf("TUNSETIFF: %w", errno)
	}
	uso := false
	if vnetHdr {
		sz := uint32(virtioNetHdrLen)
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETVNETHDRSZ), uintptr(unsafe.Pointer(&sz)))
		if errno != 0 {
			unix.Close(fd)
			return -1, "", false, fmt.Errorf("TUNSETVNETHDRSZ: %w", errno)
		}
		// Checksum + TCP segmentation offload is the always-on baseline.
		if err := tunSetOffload(fd, false); err != nil {
			unix.Close(fd)
			return -1, "", false, fmt.Errorf("TUNSETOFFLOAD: %w", err)
		}
		// Probe UDP segmentation offload, then revert to the TSO-only
		// baseline; USO is only switched on after the handshake confirms
		// the peer supports it too.
		if tunSetOffload(fd, true) == nil {
			uso = true
			_ = tunSetOffload(fd, false)
		}
	}
	return fd, string(bytes.TrimRight(req.Name[:], "\x00")), uso, nil
}
