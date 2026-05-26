//go:build linux

package packethose

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// udpBatchSize is the maximum number of UDP packets pulled out of
// the kernel per recvmmsg(2) call. 64 mirrors sing-box. Larger
// batches amortise the syscall further but risk holding the cmsg
// buffer space and adding tail latency under low load.
const udpBatchSize = 64

// mmsghdr is the kernel layout of struct mmsghdr expected by
// recvmmsg(2) and sendmmsg(2). x/sys/unix doesn't export an Mmsghdr
// type on amd64, so we declare the binary-compatible shape here.
type mmsghdr struct {
	Hdr unix.Msghdr
	Len uint32
	_   [4]byte // padding so the struct matches struct mmsghdr on 64-bit Linux
}

// udpRxBatch holds preallocated kernel-msg slots for a recvmmsg loop.
// One instance is reused across iterations of the accept loop; the
// underlying buffers are reset between calls but never reallocated.
type udpRxBatch struct {
	msgs  []mmsghdr
	iovs  []unix.Iovec
	bufs  [][]byte           // [batch] payload buffer, 65535 bytes each
	names []unix.RawSockaddrAny // [batch] sender sockaddr storage
	cbufs [][]byte           // [batch] control-msg buffer, 1024 bytes each
}

func newUDPRxBatch(n int) *udpRxBatch {
	b := &udpRxBatch{
		msgs:  make([]mmsghdr, n),
		iovs:  make([]unix.Iovec, n),
		bufs:  make([][]byte, n),
		names: make([]unix.RawSockaddrAny, n),
		cbufs: make([][]byte, n),
	}
	for i := 0; i < n; i++ {
		b.bufs[i] = make([]byte, 65535)
		b.cbufs[i] = make([]byte, 1024)
		b.iovs[i].Base = &b.bufs[i][0]
		b.iovs[i].SetLen(len(b.bufs[i]))
	}
	return b
}

// arm rebuilds the Mmsghdr pointers for the next syscall. Recvmmsg
// mutates the lengths in place so we must restore them every loop.
func (b *udpRxBatch) arm() {
	for i := range b.msgs {
		h := &b.msgs[i].Hdr
		h.Name = (*byte)(unsafe.Pointer(&b.names[i]))
		h.Namelen = uint32(unsafe.Sizeof(b.names[i]))
		h.Iov = &b.iovs[i]
		h.SetIovlen(1)
		h.Control = &b.cbufs[i][0]
		h.SetControllen(len(b.cbufs[i]))
		h.Flags = 0
		b.msgs[i].Len = 0
		b.iovs[i].SetLen(len(b.bufs[i]))
	}
}

// recvmmsg invokes SYS_RECVMMSG. Returns (count, errno). Pattern
// borrowed verbatim from sing's common/bufio/packet_batch_mmsg.go.
func recvmmsg(fd int, msgvec []mmsghdr, flags int) (int, syscall.Errno) {
	r0, _, errno := unix.Syscall6(
		unix.SYS_RECVMMSG,
		uintptr(fd),
		uintptr(unsafe.Pointer(&msgvec[0])),
		uintptr(len(msgvec)),
		uintptr(flags),
		0, 0,
	)
	if errno != 0 {
		return 0, errno
	}
	return int(r0), 0
}
