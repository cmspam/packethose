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

	// Wire frame: [type:1][len:2][payload]. type distinguishes a single
	// L3 packet from a coalesced batch.
	hdrLen       = 3
	frTypeSingle = 0
	frTypeBatch  = 1
	// maxBatch is how many small datagrams a batch frame coalesces, and
	// maxFrame caps the batch plaintext so the ciphertext stays under the
	// 16-bit length field. Batching amortizes the per-packet crypto and
	// socket-write cost that otherwise makes small-datagram UDP pps-bound.
	maxBatch = 32
	maxFrame = 60000
)

// batchReader is a PacketIO that can drain a burst of queued packets in
// one call (the kernel TUN). The lane uses it to coalesce small UDP
// datagrams into one tunnel frame.
type batchReader interface {
	ReadBatch(bufs [][]byte, lens []int) (int, error)
}

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
	if keys.encrypted {
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
	maxRead := maxPkt
	if seal != nil {
		maxRead = maxPkt - seal.overhead()
	}
	if br, ok := pio.(batchReader); ok {
		tunToSockBatch(br, c, seal, minRead, maxRead, logger)
		return
	}
	wireBuf := make([]byte, hdrLen+maxPkt+aeadMax)
	for {
		n, err := pio.Read(wireBuf[hdrLen : hdrLen+maxRead])
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
		clen := n
		if seal != nil {
			// Seal cannot overlap input and output safely, so copy out the
			// plaintext first.
			pt := append([]byte(nil), wireBuf[hdrLen:hdrLen+n]...)
			clen = len(seal.seal(wireBuf[hdrLen:hdrLen], pt))
		}
		wireBuf[0] = frTypeSingle
		binary.BigEndian.PutUint16(wireBuf[1:hdrLen], uint16(clen))
		if _, err := c.Write(wireBuf[:hdrLen+clen]); err != nil {
			logger.Printf("lane: sock write: %v", err)
			return
		}
	}
}

// tunToSockBatch coalesces a burst of queued datagrams into one tunnel
// frame: one AEAD seal and one socket write for up to maxBatch packets,
// instead of one each. A lone packet is sent as a single frame, so a
// steady GSO-coalesced TCP stream is unaffected; bursty small UDP is what
// gets the amortization.
func tunToSockBatch(br batchReader, c net.Conn, seal *frameAEAD, minRead, maxRead int, logger *log.Logger) {
	bufs := make([][]byte, maxBatch)
	for i := range bufs {
		bufs[i] = make([]byte, maxRead)
	}
	lens := make([]int, maxBatch)
	plain := make([]byte, 0, maxFrame)
	wire := make([]byte, hdrLen+maxPkt+aeadMax)

	flush := func(typ byte, payload []byte) bool {
		clen := len(payload)
		if seal == nil {
			copy(wire[hdrLen:], payload)
		} else {
			clen = len(seal.seal(wire[hdrLen:hdrLen], payload))
		}
		wire[0] = typ
		binary.BigEndian.PutUint16(wire[1:hdrLen], uint16(clen))
		if _, err := c.Write(wire[:hdrLen+clen]); err != nil {
			logger.Printf("lane: sock write: %v", err)
			return false
		}
		return true
	}

	for {
		cnt, err := br.ReadBatch(bufs, lens)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if !errors.Is(err, io.EOF) {
				logger.Printf("lane: tun readbatch: %v", err)
			}
			return
		}
		if cnt == 1 {
			if lens[0] < minRead {
				continue
			}
			if !flush(frTypeSingle, bufs[0][:lens[0]]) {
				return
			}
			continue
		}
		plain = plain[:0]
		for i := 0; i < cnt; i++ {
			n := lens[i]
			if n < minRead {
				continue
			}
			if len(plain)+2+n > maxFrame {
				if len(plain) > 0 && !flush(frTypeBatch, plain) {
					return
				}
				plain = plain[:0]
			}
			plain = binary.BigEndian.AppendUint16(plain, uint16(n))
			plain = append(plain, bufs[i][:n]...)
		}
		if len(plain) > 0 && !flush(frTypeBatch, plain) {
			return
		}
	}
}

func sockToTun(c net.Conn, pio PacketIO, open *frameAEAD, logger *log.Logger) {
	r := bufio.NewReaderSize(c, rdBufSz)
	hdr := make([]byte, hdrLen)
	wire := make([]byte, maxPkt+aeadMax)
	plain := make([]byte, maxPkt+aeadMax)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			if !errors.Is(err, io.EOF) {
				logger.Printf("lane: sock read hdr: %v", err)
			}
			return
		}
		typ := hdr[0]
		n := int(binary.BigEndian.Uint16(hdr[1:hdrLen]))
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
		pt := wire[:n]
		if open != nil {
			p, err := open.open(plain[:0], wire[:n])
			if err != nil {
				logger.Printf("lane: aead open: %v", err)
				return
			}
			pt = p
		}
		if typ == frTypeBatch {
			for len(pt) >= 2 {
				l := int(binary.BigEndian.Uint16(pt[:2]))
				pt = pt[2:]
				if l > len(pt) {
					logger.Printf("lane: malformed batch frame")
					return
				}
				if !writeTun(pio, pt[:l], logger) {
					return
				}
				pt = pt[l:]
			}
			continue
		}
		if !writeTun(pio, pt, logger) {
			return
		}
	}
}

// writeTun writes one packet to the TUN, treating transient device
// conditions as skip-and-continue. Returns false on a fatal error.
func writeTun(pio PacketIO, p []byte, logger *log.Logger) bool {
	if _, err := pio.Write(p); err != nil {
		if errors.Is(err, unix.EIO) || errors.Is(err, unix.ENETDOWN) || errors.Is(err, unix.EAGAIN) {
			return true
		}
		logger.Printf("lane: tun write: %v", err)
		return false
	}
	return true
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
