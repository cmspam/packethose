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
	hsVersion byte   = 5          // v5 adds a 16-byte username field for per-user identity
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
	userName  string

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

// Wire layout, v5 (v4 plus a leading 16-byte username field so the server
// can select the matching PSK in O(1)):
//
//   client ->
//     magic(4) || ver(1)=5 || cipher(1) || user_name(16) || nonce_c(32)
//       || client_id(16) || lane_count(1)
//       || req_v4(17) || req_v6(17)
//
//   server ->
//     magic(4) || ver(1)=5 || cipher(1)
//       || HMAC(psk, ver||cipher||user_name||nonce_c||client_id||lane_count||req_v4||req_v6)(32)
//       || nonce_s(32)
//       || asg_v4(17) || prefix_v4(1) || peer_v4(17)
//       || asg_v6(17) || prefix_v6(1) || peer_v6(17)
//
//   client ->
//     HMAC(psk, ver||cipher||user_name||nonce_s||asg_v4||prefix_v4||peer_v4||asg_v6||prefix_v6||peer_v6)(32)

const (
	clientMsgLen = 4 + 1 + 1 + userNameLen + nonceLen + clientIDLen + 1 + addrSlotLen + addrSlotLen
	serverMsgLen = 4 + 1 + 1 + macLen + nonceLen + addrSlotLen + 1 + addrSlotLen + addrSlotLen + 1 + addrSlotLen
)

func initiateHandshake(c net.Conn, psk []byte, want Cipher, userName string, clientID [clientIDLen]byte, laneCount byte, req AssignmentRequest) (laneIdentity, error) {
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

	wireName := encodeUserName(userName)
	reqV4 := encodeAddrSlot(req.V4)
	reqV6 := encodeAddrSlot(req.V6)

	msg := make([]byte, clientMsgLen)
	binary.BigEndian.PutUint32(msg[0:4], hsMagic)
	msg[4] = hsVersion
	msg[5] = byte(want)
	off := 6
	copy(msg[off:off+userNameLen], wireName[:])
	off += userNameLen
	copy(msg[off:off+nonceLen], nonceC[:])
	off += nonceLen
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
		wireName[:],
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
		wireName[:],
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
		userName:  userName,
		assigned4: decodeAddrSlot(asgV4Bytes),
		prefix4:   prefix4,
		peer4:     decodeAddrSlot(peerV4Bytes),
		assigned6: decodeAddrSlot(asgV6Bytes),
		prefix6:   prefix6,
		peer6:     decodeAddrSlot(peerV6Bytes),
	}, nil
}

// pskResolver returns the PSK to validate a client handshake against.
// The wire name is the 16-byte field from the client message; the
// resolver returns the empty user name when the legacy single-PSK
// fallback path is in use.
type pskResolver func(wireName [userNameLen]byte) (psk []byte, userName string, err error)

// acceptAssignFunc is the per-handshake hook the server uses to
// allocate addresses. It receives the identified user name so the
// pool can apply per-user quota and reservation rules.
type acceptAssignFunc func(userName string, clientID [clientIDLen]byte, req AssignmentRequest) (AssignmentResponse, error)

func acceptHandshake(c net.Conn, resolve pskResolver, assignFn acceptAssignFunc) (laneIdentity, error) {
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
	pos := 6
	var wireName [userNameLen]byte
	copy(wireName[:], hdr[pos:pos+userNameLen])
	pos += userNameLen
	nonceC := hdr[pos : pos+nonceLen]
	pos += nonceLen
	var clientID [clientIDLen]byte
	copy(clientID[:], hdr[pos:pos+clientIDLen])
	pos += clientIDLen
	laneCount := hdr[pos]
	pos++
	reqV4Bytes := hdr[pos : pos+addrSlotLen]
	pos += addrSlotLen
	reqV6Bytes := hdr[pos : pos+addrSlotLen]

	psk, userName, err := resolve(wireName)
	if err != nil {
		return laneIdentity{}, err
	}
	if len(psk) == 0 {
		return laneIdentity{}, fmt.Errorf("handshake: no PSK configured")
	}

	req := AssignmentRequest{
		V4: decodeAddrSlot(reqV4Bytes),
		V6: decodeAddrSlot(reqV6Bytes),
	}
	var asg AssignmentResponse
	if assignFn != nil {
		asg, err = assignFn(userName, clientID, req)
		if err != nil {
			return laneIdentity{}, err
		}
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
		wireName[:],
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
		wireName[:],
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
		userName:  userName,
		assigned4: asg.V4Addr,
		prefix4:   asg.V4Prefix,
		peer4:     asg.V4Peer,
		assigned6: asg.V6Addr,
		prefix6:   asg.V6Prefix,
		peer6:     asg.V6Peer,
	}, nil
}

// singlePSKResolver returns a pskResolver that always returns the
// given PSK, ignoring the wire name. Used by the legacy single-PSK
// server path.
func singlePSKResolver(psk []byte) pskResolver {
	return func(wireName [userNameLen]byte) ([]byte, string, error) {
		return psk, decodeUserName(wireName), nil
	}
}

// userDBResolver returns a pskResolver that selects the PSK matching
// the wire name. A non-empty legacyPSK is returned when the wire name
// is empty so old call sites with a single shared PSK still work; an
// unknown name returns ErrUnknownUser.
func userDBResolver(db *UserDB, legacyPSK []byte) pskResolver {
	return func(wireName [userNameLen]byte) ([]byte, string, error) {
		name := decodeUserName(wireName)
		if name == "" {
			if len(legacyPSK) == 0 {
				return nil, "", fmt.Errorf("handshake: client did not send user name and no legacy PSK is configured")
			}
			return legacyPSK, "", nil
		}
		u := db.Lookup(wireName)
		if u == nil {
			return nil, "", ErrUnknownUser
		}
		return u.PSK, u.Name, nil
	}
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
