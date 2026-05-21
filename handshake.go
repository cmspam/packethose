package packethose

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"
)

const (
	hsMagic   uint32 = 0x50484F53 // "PHOS"
	hsVersion byte   = 3
	hsTimeout        = 5 * time.Second
	nonceLen         = 32
	macLen           = 32
	clientIDLen      = 16
)

// laneIdentity carries the data exchanged by the v3 handshake that the lane
// supervisors need to know about: the cipher, derived session keys, and (when
// the server is in multi-client mode) the server-allocated tunnel address.
type laneIdentity struct {
	keys       laneKeys
	clientID   [clientIDLen]byte
	laneCount  byte
	assignedIP netip.Addr
	peerIP     netip.Addr
	prefixLen  byte // 0 = no assignment
}

// initiateHandshake (client). With psk==nil and want==CipherNone, no handshake
// runs. Otherwise v3 runs:
//
//   client -> magic(4) ver(1)=3 cipher(1) nonce_c(32) clientID(16) laneCount(1) reqIP(4)
//   server -> magic(4) ver(1)=3 cipher(1) HMAC(psk, ver||cipher||nonce_c||clientID||laneCount||reqIP)(32)
//             nonce_s(32) assignedIP(4) prefix(1) peerIP(4)
//   client -> HMAC(psk, ver||cipher||nonce_s||assignedIP||prefix||peerIP)(32)
//
// reqIP=0.0.0.0 means "any". assignedIP=0.0.0.0 + prefix=0 means the server
// is in single-client mode and the client should use its locally configured
// address.
func initiateHandshake(c net.Conn, psk []byte, want Cipher, clientID [clientIDLen]byte, laneCount byte, reqIP netip.Addr) (laneIdentity, error) {
	if len(psk) == 0 {
		if want != CipherNone {
			return laneIdentity{}, fmt.Errorf("encrypt requires PSK")
		}
		return laneIdentity{clientID: clientID, laneCount: laneCount}, nil
	}
	c.SetDeadline(time.Now().Add(hsTimeout))
	defer c.SetDeadline(time.Time{})

	var nonceC [nonceLen]byte
	if _, err := rand.Read(nonceC[:]); err != nil {
		return laneIdentity{}, err
	}
	reqIP4 := zeroAddrV4()
	if reqIP.Is4() {
		reqIP4 = reqIP
	}
	hdr := make([]byte, 4+1+1+nonceLen+clientIDLen+1+4)
	binary.BigEndian.PutUint32(hdr[0:4], hsMagic)
	hdr[4] = hsVersion
	hdr[5] = byte(want)
	copy(hdr[6:6+nonceLen], nonceC[:])
	copy(hdr[6+nonceLen:6+nonceLen+clientIDLen], clientID[:])
	hdr[6+nonceLen+clientIDLen] = laneCount
	copy(hdr[6+nonceLen+clientIDLen+1:], reqIP4.AsSlice())
	if _, err := c.Write(hdr); err != nil {
		return laneIdentity{}, err
	}

	resp := make([]byte, 4+1+1+macLen+nonceLen+4+1+4)
	if _, err := io.ReadFull(c, resp); err != nil {
		return laneIdentity{}, err
	}
	if binary.BigEndian.Uint32(resp[0:4]) != hsMagic {
		return laneIdentity{}, fmt.Errorf("handshake: bad magic")
	}
	if resp[4] != hsVersion {
		return laneIdentity{}, fmt.Errorf("handshake: version mismatch (got %d, want %d)", resp[4], hsVersion)
	}
	got := Cipher(resp[5])
	if got != want {
		return laneIdentity{}, fmt.Errorf("handshake: cipher rejected (sent %s, got %s)", want, got)
	}
	authIn := concat([]byte{hsVersion, byte(got)}, nonceC[:], clientID[:], []byte{laneCount}, reqIP4.AsSlice())
	if !hmac.Equal(hmacSHA256(psk, authIn), resp[6:6+macLen]) {
		return laneIdentity{}, fmt.Errorf("handshake: server HMAC mismatch")
	}
	nonceS := resp[6+macLen : 6+macLen+nonceLen]
	assignedIPBytes := resp[6+macLen+nonceLen : 6+macLen+nonceLen+4]
	prefix := resp[6+macLen+nonceLen+4]
	peerIPBytes := resp[6+macLen+nonceLen+5 : 6+macLen+nonceLen+9]

	cliAuth := concat([]byte{hsVersion, byte(got)}, nonceS, assignedIPBytes, []byte{prefix}, peerIPBytes)
	if _, err := c.Write(hmacSHA256(psk, cliAuth)); err != nil {
		return laneIdentity{}, err
	}

	tx, rx, err := deriveSessionKeys(psk, nonceC[:], nonceS, got, false)
	if err != nil {
		return laneIdentity{}, err
	}
	id := laneIdentity{
		keys:      laneKeys{kind: got, tx: tx, rx: rx},
		clientID:  clientID,
		laneCount: laneCount,
		prefixLen: prefix,
	}
	if prefix != 0 {
		id.assignedIP, _ = netip.AddrFromSlice(assignedIPBytes)
		id.peerIP, _ = netip.AddrFromSlice(peerIPBytes)
	}
	return id, nil
}

// acceptHandshake (server). Mirror of initiateHandshake; uses assignFn to
// pick the assigned address from the server's IP pool (or zero for
// single-client servers that pass an assignFn returning zero).
func acceptHandshake(c net.Conn, psk []byte, assignFn func(clientID [clientIDLen]byte, requested netip.Addr) (assigned, peer netip.Addr, prefix byte)) (laneIdentity, error) {
	if len(psk) == 0 {
		return laneIdentity{}, nil
	}
	c.SetDeadline(time.Now().Add(hsTimeout))
	defer c.SetDeadline(time.Time{})

	hdr := make([]byte, 4+1+1+nonceLen+clientIDLen+1+4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return laneIdentity{}, err
	}
	if binary.BigEndian.Uint32(hdr[0:4]) != hsMagic {
		return laneIdentity{}, fmt.Errorf("handshake: bad magic")
	}
	if hdr[4] != hsVersion {
		return laneIdentity{}, fmt.Errorf("handshake: version mismatch (got %d, want %d)", hdr[4], hsVersion)
	}
	got := Cipher(hdr[5])
	if got != CipherNone && got != CipherAESGCM && got != CipherChaCha {
		return laneIdentity{}, fmt.Errorf("handshake: unknown cipher %d", got)
	}
	nonceC := hdr[6 : 6+nonceLen]
	var clientID [clientIDLen]byte
	copy(clientID[:], hdr[6+nonceLen:6+nonceLen+clientIDLen])
	laneCount := hdr[6+nonceLen+clientIDLen]
	reqIPBytes := hdr[6+nonceLen+clientIDLen+1:]
	reqIP, _ := netip.AddrFromSlice(reqIPBytes)

	var assigned, peer netip.Addr
	var prefix byte
	if assignFn != nil {
		assigned, peer, prefix = assignFn(clientID, reqIP)
	}
	if !assigned.IsValid() {
		assigned = zeroAddrV4()
	}
	if !peer.IsValid() {
		peer = zeroAddrV4()
	}

	var nonceS [nonceLen]byte
	if _, err := rand.Read(nonceS[:]); err != nil {
		return laneIdentity{}, err
	}

	resp := make([]byte, 4+1+1+macLen+nonceLen+4+1+4)
	binary.BigEndian.PutUint32(resp[0:4], hsMagic)
	resp[4] = hsVersion
	resp[5] = byte(got)
	authIn := concat([]byte{hsVersion, byte(got)}, nonceC, clientID[:], []byte{laneCount}, reqIPBytes)
	copy(resp[6:6+macLen], hmacSHA256(psk, authIn))
	copy(resp[6+macLen:6+macLen+nonceLen], nonceS[:])
	copy(resp[6+macLen+nonceLen:6+macLen+nonceLen+4], assigned.AsSlice())
	resp[6+macLen+nonceLen+4] = prefix
	copy(resp[6+macLen+nonceLen+5:], peer.AsSlice())
	if _, err := c.Write(resp); err != nil {
		return laneIdentity{}, err
	}

	ack := make([]byte, macLen)
	if _, err := io.ReadFull(c, ack); err != nil {
		return laneIdentity{}, err
	}
	cliAuth := concat([]byte{hsVersion, byte(got)}, nonceS[:], assigned.AsSlice(), []byte{prefix}, peer.AsSlice())
	if !bytes.Equal(hmacSHA256(psk, cliAuth), ack) {
		return laneIdentity{}, fmt.Errorf("handshake: client HMAC mismatch")
	}

	tx, rx, err := deriveSessionKeys(psk, nonceC, nonceS[:], got, true)
	if err != nil {
		return laneIdentity{}, err
	}
	return laneIdentity{
		keys:       laneKeys{kind: got, tx: tx, rx: rx},
		clientID:   clientID,
		laneCount:  laneCount,
		assignedIP: assigned,
		peerIP:     peer,
		prefixLen:  prefix,
	}, nil
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func concat(parts ...[]byte) []byte {
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	out := make([]byte, 0, total)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func zeroAddrV4() netip.Addr {
	return netip.AddrFrom4([4]byte{})
}
