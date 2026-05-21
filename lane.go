package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	maxPkt    = 65535
	rdBufSz   = 4 << 20  // 4 MB — big batches help kernel TSO/GRO ride through reorder
	sockBufSz = 32 << 20 // 32 MB SO_SNDBUF/SO_RCVBUF target
	aeadMax   = 32       // upper bound on AEAD overhead for both supported ciphers
)

// runLane operates one tun-fd ↔ socket pair until either side closes.
// CPU pinning was tried and consistently regressed throughput on small VMs:
// the Linux scheduler already co-locates goroutines with the NIC/TUN softirq
// CPU, and static affinity gets in the way of that.
func runLane(id int, tunFd int, c net.Conn, keys laneKeys) {
	defer c.Close()
	tuneSocket(c)

	var seal, open *frameAEAD
	if keys.kind != cipherNone {
		var err error
		if seal, err = newFrameAEAD(keys.kind, keys.tx); err != nil {
			log.Printf("lane %d: tx aead init: %v", id, err)
			return
		}
		if open, err = newFrameAEAD(keys.kind, keys.rx); err != nil {
			log.Printf("lane %d: rx aead init: %v", id, err)
			return
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); tunToSock(id, tunFd, c, seal) }()
	go func() { defer wg.Done(); sockToTun(id, c, tunFd, open) }()
	wg.Wait()
}

func tunToSock(id, tunFd int, c net.Conn, seal *frameAEAD) {
	// Two buffers: TUN read into pktBuf, wire write from wireBuf.
	// In plaintext mode, pktBuf is wireBuf[2:] (zero copy).
	// In encrypted mode, seal writes ciphertext into wireBuf[2:].
	wireBuf := make([]byte, 2+maxPkt+aeadMax)
	maxRead := maxPkt
	if seal != nil {
		maxRead = maxPkt - seal.overhead()
	}
	for {
		n, err := unix.Read(tunFd, wireBuf[2:2+maxRead])
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			log.Printf("lane %d: tun read: %v", id, err)
			return
		}
		if n <= 0 {
			continue
		}
		var clen int
		if seal == nil {
			clen = n
		} else {
			// Seal in place: plaintext is wireBuf[2:2+n]; ciphertext appended
			// at wireBuf[2:]. Since dst==plaintext start they alias but Seal
			// supports this when capacity allows.
			pt := append([]byte(nil), wireBuf[2:2+n]...) // small alloc, safe overlap
			ct := seal.seal(wireBuf[2:2], pt)
			clen = len(ct)
		}
		binary.BigEndian.PutUint16(wireBuf[:2], uint16(clen))
		if _, err := c.Write(wireBuf[:2+clen]); err != nil {
			log.Printf("lane %d: sock write: %v", id, err)
			return
		}
	}
}

func sockToTun(id int, c net.Conn, tunFd int, open *frameAEAD) {
	r := bufio.NewReaderSize(c, rdBufSz)
	hdr := make([]byte, 2)
	wire := make([]byte, maxPkt+aeadMax)
	plain := make([]byte, maxPkt+aeadMax)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			if err != io.EOF {
				log.Printf("lane %d: sock read hdr: %v", id, err)
			}
			return
		}
		n := int(binary.BigEndian.Uint16(hdr))
		if n == 0 {
			continue
		}
		if n > len(wire) {
			log.Printf("lane %d: oversize frame %d", id, n)
			return
		}
		if _, err := io.ReadFull(r, wire[:n]); err != nil {
			log.Printf("lane %d: sock read body: %v", id, err)
			return
		}
		var out []byte
		if open == nil {
			out = wire[:n]
		} else {
			pt, err := open.open(plain[:0], wire[:n])
			if err != nil {
				log.Printf("lane %d: aead open: %v", id, err)
				return
			}
			out = pt
		}
		if _, err := unix.Write(tunFd, out); err != nil {
			if errors.Is(err, unix.EIO) || errors.Is(err, unix.ENETDOWN) || errors.Is(err, unix.EAGAIN) {
				continue
			}
			log.Printf("lane %d: tun write: %v", id, err)
			return
		}
	}
}

func tuneSocket(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetNoDelay(true)
	sc, err := tc.SyscallConn()
	if err != nil {
		return
	}
	_ = sc.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, sockBufSz)
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, sockBufSz)
	})
}
