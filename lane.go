package packethose

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	maxPkt    = 65535
	rdBufSz   = 4 << 20  // 4 MB — big batches help kernel TSO/GRO ride through reorder
	sockBufSz = 32 << 20 // 32 MB SO_SNDBUF/SO_RCVBUF target
	aeadMax   = 32       // upper bound on AEAD overhead for both supported ciphers
)

// runLane drives a single TUN-queue ↔ outer-socket lane to first I/O error
// on either side. Bidirectional copy with optional AEAD framing.
//
// The lane does not loop on error; the caller (a supervisor) decides whether
// to reconnect.
func runLane(pio PacketIO, c net.Conn, keys laneKeys, extraTune func(net.Conn), logger *log.Logger) {
	defer c.Close()
	tuneSocket(c)
	if extraTune != nil {
		extraTune(c)
	}

	var seal, open *frameAEAD
	if keys.kind != CipherNone {
		var err error
		if seal, err = newFrameAEAD(keys.kind, keys.tx); err != nil {
			logger.Printf("lane: tx aead init: %v", err)
			return
		}
		if open, err = newFrameAEAD(keys.kind, keys.rx); err != nil {
			logger.Printf("lane: rx aead init: %v", err)
			return
		}
	}

	minRead := 1
	if pio.VnetHdr() {
		minRead = virtioNetHdrLen + 1
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); tunToSock(pio, c, seal, minRead, logger) }()
	go func() { defer wg.Done(); sockToTun(c, pio, open, logger) }()
	wg.Wait()
}

func tunToSock(pio PacketIO, c net.Conn, seal *frameAEAD, minRead int, logger *log.Logger) {
	wireBuf := make([]byte, 2+maxPkt+aeadMax)
	maxRead := maxPkt
	if seal != nil {
		maxRead = maxPkt - seal.overhead()
	}
	for {
		n, err := pio.Read(wireBuf[2 : 2+maxRead])
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if !errors.Is(err, io.EOF) {
				logger.Printf("lane: tun read: %v", err)
			}
			return
		}
		if n < minRead {
			continue
		}
		var clen int
		if seal == nil {
			clen = n
		} else {
			// Seal cannot overlap input and output safely, so copy out the
			// plaintext first. The alloc is tiny relative to TLS in flight.
			pt := append([]byte(nil), wireBuf[2:2+n]...)
			ct := seal.seal(wireBuf[2:2], pt)
			clen = len(ct)
		}
		binary.BigEndian.PutUint16(wireBuf[:2], uint16(clen))
		if _, err := c.Write(wireBuf[:2+clen]); err != nil {
			logger.Printf("lane: sock write: %v", err)
			return
		}
	}
}

func sockToTun(c net.Conn, pio PacketIO, open *frameAEAD, logger *log.Logger) {
	r := bufio.NewReaderSize(c, rdBufSz)
	hdr := make([]byte, 2)
	wire := make([]byte, maxPkt+aeadMax)
	plain := make([]byte, maxPkt+aeadMax)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			if !errors.Is(err, io.EOF) {
				logger.Printf("lane: sock read hdr: %v", err)
			}
			return
		}
		n := int(binary.BigEndian.Uint16(hdr))
		if n == 0 {
			continue
		}
		if n > len(wire) {
			logger.Printf("lane: oversize frame %d", n)
			return
		}
		if _, err := io.ReadFull(r, wire[:n]); err != nil {
			logger.Printf("lane: sock read body: %v", err)
			return
		}
		var out []byte
		if open == nil {
			out = wire[:n]
		} else {
			pt, err := open.open(plain[:0], wire[:n])
			if err != nil {
				logger.Printf("lane: aead open: %v", err)
				return
			}
			out = pt
		}
		if _, err := pio.Write(out); err != nil {
			if errors.Is(err, unix.EIO) || errors.Is(err, unix.ENETDOWN) || errors.Is(err, unix.EAGAIN) {
				continue
			}
			logger.Printf("lane: tun write: %v", err)
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
	_ = tc.SetKeepAlive(true)
	_ = tc.SetKeepAlivePeriod(15 * time.Second)
	sc, err := tc.SyscallConn()
	if err != nil {
		return
	}
	_ = sc.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, sockBufSz)
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, sockBufSz)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPIDLE, 15)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPINTVL, 5)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPCNT, 3)
	})
	_ = applyBBR(c)
}
