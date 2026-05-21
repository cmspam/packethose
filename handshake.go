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
	hsVersion byte   = 4          // v4: dual-stack address fields (v4 + v6)
	hsTimeout        = 5 * time.Second
	nonceLen         = 32
	macLen           = 32
	clientIDLen      = 16

	// On-wire address slot: family(1) || addr(16). family ∈ {0,4,6}.
	addrSlotLen = 17
)

// laneIdentity carries what the lane supervisors need: the cipher, derived
// session keys, the client identity, and (in multi-client mode) the
// server-assigned tunnel addresses for IPv4 and/or IPv6.
type laneIdentity struct {
	keys      laneKeys
	clientID  [clientIDLen]byte
	laneCount byte

	assigned4 netip.Addr
	prefix4   byte
	peer4     netip.Addr

	assigned6 netip.Addr
	prefix6   byte
	peer6     netip.Addr
}

func (id laneIdentity) hasAssignment() bool {
	return (id.prefix4 != 0 && id.assigned4.IsValid()) ||
		(id.prefix6 != 0 && id.assigned6.IsValid())
}

// encodeAddrSlot returns 17 bytes: family(1) + addr(16). family=0 means
// "unspecified" and addr is zero-padded.
func encodeAddrSlot(a netip.Addr) []byte {
	out := make([]byte, addrSlotLen)
	switch {
	case !a.IsValid() || a.IsUnspecified():
		out[0] = 0
	case a.Is4():
		out[0] = 4
		copy(out[1:5], a.AsSlice())
	case a.Is6():
		out[0] = 6
		copy(out[1:17], a.AsSlice())
	}
	return out
}

func decodeAddrSlot(b []byte) netip.Addr {
	if len(b) < addrSlotLen {
		return netip.Addr{}
	}
	switch b[0] {
	case 4:
		var a [4]byte
		copy(a[:], b[1:5])
		return netip.AddrFrom4(a)
	case 6:
		var a [16]byte
		copy(a[:], b[1:17])
		return netip.AddrFrom16(a)
	}
	return netip.Addr{}
}

// AssignmentRequest is what the client asks for in its handshake.
type AssignmentRequest struct {
	V4 netip.Addr // zero / Is4() == false ⇒ no v4 request
	V6 netip.Addr // zero / Is6() == false ⇒ no v6 request
}

// AssignmentResponse is what the server returns. A family with prefix == 0
// means the server did not assign that family.
type AssignmentResponse struct {
	V4Addr   netip.Addr
	V4Prefix byte
	V4Peer   netip.Addr

	V6Addr   netip.Addr
	V6Prefix byte
	V6Peer   netip.Addr
}

// AssignFunc is the server-side hook that picks per-family addresses for an
// incoming client. Implementations return zero / 0-prefix to decline a family.
type AssignFunc func(clientID [clientIDLen]byte, req AssignmentRequest) AssignmentResponse

// Wire layout, v4:
//
//   client ->
//     magic(4) || ver(1)=4 || cipher(1) || nonce_c(32)
//       || client_id(16) || lane_count(1)
//       || req_v4(17) || req_v6(17)
//
//   server ->
//     magic(4) || ver(1)=4 || cipher(1)
//       || HMAC(psk, ver||cipher||nonce_c||client_id||lane_count||req_v4||req_v6)(32)
//       || nonce_s(32)
//       || asg_v4(17) || prefix_v4(1) || peer_v4(17)
//       || asg_v6(17) || prefix_v6(1) || peer_v6(17)
//
//   client ->
//     HMAC(psk, ver||cipher||nonce_s||asg_v4||prefix_v4||peer_v4||asg_v6||prefix_v6||peer_v6)(32)

const (
	clientMsgLen = 4 + 1 + 1 + nonceLen + clientIDLen + 1 + addrSlotLen + addrSlotLen
	serverMsgLen = 4 + 1 + 1 + macLen + nonceLen + addrSlotLen + 1 + addrSlotLen + addrSlotLen + 1 + addrSlotLen
)

func initiateHandshake(c net.Conn, psk []byte, want Cipher, clientID [clientIDLen]byte, laneCount byte, req AssignmentRequest) (laneIdentity, error) {
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

	reqV4 := encodeAddrSlot(req.V4)
	reqV6 := encodeAddrSlot(req.V6)

	msg := make([]byte, clientMsgLen)
	binary.BigEndian.PutUint32(msg[0:4], hsMagic)
	msg[4] = hsVersion
	msg[5] = byte(want)
	copy(msg[6:6+nonceLen], nonceC[:])
	off := 6 + nonceLen
	copy(msg[off:off+clientIDLen], clientID[:])
	off += clientIDLen
	msg[off] = laneCount
	off++
	copy(msg[off:off+addrSlotLen], reqV4)
	off += addrSlotLen
	copy(msg[off:off+addrSlotLen], reqV6)

	if _, err := c.Write(msg); err != nil {
		return laneIdentity{}, err
	}

	resp := make([]byte, serverMsgLen)
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
	authIn := concat(
		[]byte{hsVersion, byte(got)},
		nonceC[:],
		clientID[:],
		[]byte{laneCount},
		reqV4,
		reqV6,
	)
	if !hmac.Equal(hmacSHA256(psk, authIn), resp[6:6+macLen]) {
		return laneIdentity{}, fmt.Errorf("handshake: server HMAC mismatch")
	}

	pos := 6 + macLen
	nonceS := resp[pos : pos+nonceLen]
	pos += nonceLen
	asgV4Bytes := resp[pos : pos+addrSlotLen]
	pos += addrSlotLen
	prefix4 := resp[pos]
	pos++
	peerV4Bytes := resp[pos : pos+addrSlotLen]
	pos += addrSlotLen
	asgV6Bytes := resp[pos : pos+addrSlotLen]
	pos += addrSlotLen
	prefix6 := resp[pos]
	pos++
	peerV6Bytes := resp[pos : pos+addrSlotLen]

	cliAuth := concat(
		[]byte{hsVersion, byte(got)},
		nonceS,
		asgV4Bytes, []byte{prefix4}, peerV4Bytes,
		asgV6Bytes, []byte{prefix6}, peerV6Bytes,
	)
	if _, err := c.Write(hmacSHA256(psk, cliAuth)); err != nil {
		return laneIdentity{}, err
	}

	tx, rx, err := deriveSessionKeys(psk, nonceC[:], nonceS, got, false)
	if err != nil {
		return laneIdentity{}, err
	}
	return laneIdentity{
		keys:      laneKeys{kind: got, tx: tx, rx: rx},
		clientID:  clientID,
		laneCount: laneCount,
		assigned4: decodeAddrSlot(asgV4Bytes),
		prefix4:   prefix4,
		peer4:     decodeAddrSlot(peerV4Bytes),
		assigned6: decodeAddrSlot(asgV6Bytes),
		prefix6:   prefix6,
		peer6:     decodeAddrSlot(peerV6Bytes),
	}, nil
}

func acceptHandshake(c net.Conn, psk []byte, assignFn AssignFunc) (laneIdentity, error) {
	if len(psk) == 0 {
		return laneIdentity{}, nil
	}
	c.SetDeadline(time.Now().Add(hsTimeout))
	defer c.SetDeadline(time.Time{})

	hdr := make([]byte, clientMsgLen)
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
	pos := 6 + nonceLen
	var clientID [clientIDLen]byte
	copy(clientID[:], hdr[pos:pos+clientIDLen])
	pos += clientIDLen
	laneCount := hdr[pos]
	pos++
	reqV4Bytes := hdr[pos : pos+addrSlotLen]
	pos += addrSlotLen
	reqV6Bytes := hdr[pos : pos+addrSlotLen]

	req := AssignmentRequest{
		V4: decodeAddrSlot(reqV4Bytes),
		V6: decodeAddrSlot(reqV6Bytes),
	}
	var asg AssignmentResponse
	if assignFn != nil {
		asg = assignFn(clientID, req)
	}

	var nonceS [nonceLen]byte
	if _, err := rand.Read(nonceS[:]); err != nil {
		return laneIdentity{}, err
	}

	asgV4 := encodeAddrSlot(asg.V4Addr)
	peerV4 := encodeAddrSlot(asg.V4Peer)
	asgV6 := encodeAddrSlot(asg.V6Addr)
	peerV6 := encodeAddrSlot(asg.V6Peer)

	resp := make([]byte, serverMsgLen)
	binary.BigEndian.PutUint32(resp[0:4], hsMagic)
	resp[4] = hsVersion
	resp[5] = byte(got)
	authIn := concat(
		[]byte{hsVersion, byte(got)},
		nonceC, clientID[:],
		[]byte{laneCount},
		reqV4Bytes, reqV6Bytes,
	)
	copy(resp[6:6+macLen], hmacSHA256(psk, authIn))
	pos = 6 + macLen
	copy(resp[pos:pos+nonceLen], nonceS[:])
	pos += nonceLen
	copy(resp[pos:pos+addrSlotLen], asgV4)
	pos += addrSlotLen
	resp[pos] = asg.V4Prefix
	pos++
	copy(resp[pos:pos+addrSlotLen], peerV4)
	pos += addrSlotLen
	copy(resp[pos:pos+addrSlotLen], asgV6)
	pos += addrSlotLen
	resp[pos] = asg.V6Prefix
	pos++
	copy(resp[pos:pos+addrSlotLen], peerV6)

	if _, err := c.Write(resp); err != nil {
		return laneIdentity{}, err
	}

	ack := make([]byte, macLen)
	if _, err := io.ReadFull(c, ack); err != nil {
		return laneIdentity{}, err
	}
	cliAuth := concat(
		[]byte{hsVersion, byte(got)},
		nonceS[:],
		asgV4, []byte{asg.V4Prefix}, peerV4,
		asgV6, []byte{asg.V6Prefix}, peerV6,
	)
	if !bytes.Equal(hmacSHA256(psk, cliAuth), ack) {
		return laneIdentity{}, fmt.Errorf("handshake: client HMAC mismatch")
	}

	tx, rx, err := deriveSessionKeys(psk, nonceC, nonceS[:], got, true)
	if err != nil {
		return laneIdentity{}, err
	}
	return laneIdentity{
		keys:      laneKeys{kind: got, tx: tx, rx: rx},
		clientID:  clientID,
		laneCount: laneCount,
		assigned4: asg.V4Addr,
		prefix4:   asg.V4Prefix,
		peer4:     asg.V4Peer,
		assigned6: asg.V6Addr,
		prefix6:   asg.V6Prefix,
		peer6:     asg.V6Peer,
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
