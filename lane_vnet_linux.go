//go:build linux

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

const virtioNetHdrLen = 10

// runLaneVnetHdr operates a lane on a TUN device opened with IFF_VNET_HDR.
// Wire format mirrors the plain lane but each frame's payload is
// vnet_hdr(10) || L3-super-packet, optionally wrapped by AEAD.
func runLaneVnetHdr(id int, tunFd int, c net.Conn, keys laneKeys) {
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
	go func() { defer wg.Done(); tunToSockVnet(id, tunFd, c, seal) }()
	go func() { defer wg.Done(); sockToTunVnet(id, c, tunFd, open) }()
	wg.Wait()
}

func tunToSockVnet(id, tunFd int, c net.Conn, seal *frameAEAD) {
	const maxFrame = 65535 // uint16 length cap
	wireBuf := make([]byte, 2+maxFrame+aeadMax)
	maxRead := maxFrame
	if seal != nil {
		maxRead = maxFrame - seal.overhead()
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
		if n <= virtioNetHdrLen {
			continue
		}
		var clen int
		if seal == nil {
			clen = n
		} else {
			pt := append([]byte(nil), wireBuf[2:2+n]...)
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

func sockToTunVnet(id int, c net.Conn, tunFd int, open *frameAEAD) {
	r := bufio.NewReaderSize(c, rdBufSz)
	hdr := make([]byte, 2)
	wire := make([]byte, 65535+aeadMax)
	plain := make([]byte, 65535+aeadMax)
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
