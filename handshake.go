package packethose

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/flynn/noise"
)

const (
	hsVersion   byte = 7 // v7: Noise_IK static-key identity over the obfuscation envelope
	nonceLen         = 32
	clientIDLen      = 16
	pubKeyLen        = 32

	// On-wire address slot: family(1) || addr(16). family ∈ {0,4,6}.
	addrSlotLen = 17

	// Handshake payload sizes (carried inside the Noise messages, which
	// are themselves carried inside the obfuscation envelope). The trailing
	// byte of each is a capability/flags field.
	clientPayloadLen = 1 + 1 + 1 + addrSlotLen + addrSlotLen + 1 // ver, cipher, lane_count, req_v4, req_v6, flags
	serverPayloadLen = 1 + addrSlotLen + 1 + addrSlotLen + addrSlotLen + 1 + addrSlotLen + 1

	// hsFlagUSO marks the sender as able to do UDP segmentation offload.
	// USO is used only when both peers set it.
	hsFlagUSO byte = 1 << 0
)

// hsPrologue binds both peers to the protocol identity; a mismatch makes
// the Noise handshake fail.
var hsPrologue = []byte("packethose-v7")

// hsTimeout bounds how long a handshake may take. A malformed or stalled
// peer is held until this elapses and then dropped, which also slows
// connection-flood probing. It is a var so tests can shorten it.
var hsTimeout = 5 * time.Second

// laneIdentity carries what the lane supervisors need: the transport
// ciphers, the client identity (its static public key and the derived
// session id), and (in multi-client mode) the server-assigned tunnel
// addresses.
type laneIdentity struct {
	keys       laneKeys
	clientID   [clientIDLen]byte
	pubKey     []byte
	laneCount  byte
	userName   string
	usoEnabled bool // both peers support UDP segmentation offload

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
	V4 netip.Addr
	V6 netip.Addr
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

// AssignFunc is the server-side hook that picks per-family addresses.
type AssignFunc func(clientID [clientIDLen]byte, req AssignmentRequest) AssignmentResponse

// pubKeyAuthorizer authorizes a client by its static public key,
// returning the human-readable user name (empty in single-peer mode) or
// an error to reject. It runs before any address is allocated, so an
// unauthorized peer can never drive an allocation.
type pubKeyAuthorizer func(clientPub []byte) (userName string, err error)

// acceptAssignFunc is the server-side address-allocation hook, invoked
// only after the client's static key has been authorized.
type acceptAssignFunc func(userName string, clientID [clientIDLen]byte, req AssignmentRequest) (AssignmentResponse, error)

// serverAuthorizer builds a pubKeyAuthorizer from the configured client
// identities: the multi-client user DB when populated, otherwise the
// single authorized peer public key. Public keys are not secret, so a
// plain comparison is fine.
func serverAuthorizer(users *UserDB, peerPub []byte) pubKeyAuthorizer {
	return func(clientPub []byte) (string, error) {
		if users != nil && !users.Empty() {
			u := users.LookupByKey(clientPub)
			if u == nil {
				return "", ErrUnknownUser
			}
			return u.Name, nil
		}
		if len(peerPub) > 0 && bytes.Equal(clientPub, peerPub) {
			return "", nil
		}
		return "", ErrUnknownUser
	}
}

func usoFlag(uso bool) byte {
	if uso {
		return hsFlagUSO
	}
	return 0
}

func buildClientPayload(cipher Cipher, laneCount byte, req AssignmentRequest, uso bool) []byte {
	out := make([]byte, 0, clientPayloadLen)
	out = append(out, hsVersion, byte(cipher), laneCount)
	out = append(out, encodeAddrSlot(req.V4)...)
	out = append(out, encodeAddrSlot(req.V6)...)
	out = append(out, usoFlag(uso))
	return out
}

func parseClientPayload(p []byte) (cipher Cipher, laneCount byte, req AssignmentRequest, uso bool, err error) {
	if len(p) < clientPayloadLen {
		return 0, 0, AssignmentRequest{}, false, fmt.Errorf("handshake: short client payload")
	}
	if p[0] != hsVersion {
		return 0, 0, AssignmentRequest{}, false, fmt.Errorf("handshake: version mismatch (got %d, want %d)", p[0], hsVersion)
	}
	cipher = Cipher(p[1])
	laneCount = p[2]
	req.V4 = decodeAddrSlot(p[3 : 3+addrSlotLen])
	req.V6 = decodeAddrSlot(p[3+addrSlotLen : 3+2*addrSlotLen])
	uso = p[3+2*addrSlotLen]&hsFlagUSO != 0
	return cipher, laneCount, req, uso, nil
}

func buildServerPayload(asg AssignmentResponse, uso bool) []byte {
	out := make([]byte, 0, serverPayloadLen)
	out = append(out, hsVersion)
	out = append(out, encodeAddrSlot(asg.V4Addr)...)
	out = append(out, asg.V4Prefix)
	out = append(out, encodeAddrSlot(asg.V4Peer)...)
	out = append(out, encodeAddrSlot(asg.V6Addr)...)
	out = append(out, asg.V6Prefix)
	out = append(out, encodeAddrSlot(asg.V6Peer)...)
	out = append(out, usoFlag(uso))
	return out
}

func parseServerPayload(p []byte) (asg AssignmentResponse, uso bool, err error) {
	if len(p) < serverPayloadLen {
		return AssignmentResponse{}, false, fmt.Errorf("handshake: short server payload")
	}
	if p[0] != hsVersion {
		return AssignmentResponse{}, false, fmt.Errorf("handshake: version mismatch (got %d, want %d)", p[0], hsVersion)
	}
	pos := 1
	asg.V4Addr = decodeAddrSlot(p[pos : pos+addrSlotLen])
	pos += addrSlotLen
	asg.V4Prefix = p[pos]
	pos++
	asg.V4Peer = decodeAddrSlot(p[pos : pos+addrSlotLen])
	pos += addrSlotLen
	asg.V6Addr = decodeAddrSlot(p[pos : pos+addrSlotLen])
	pos += addrSlotLen
	asg.V6Prefix = p[pos]
	pos++
	asg.V6Peer = decodeAddrSlot(p[pos : pos+addrSlotLen])
	pos += addrSlotLen
	uso = p[pos]&hsFlagUSO != 0
	return asg, uso, nil
}

// initiateHandshake runs the client (Noise initiator) side. static is
// the client's own static keypair; serverPub is the server's static
// public key, known in advance (the IK pre-message). The obfuscation
// envelope is keyed by serverPub.
func initiateHandshake(c net.Conn, static noise.DHKey, serverPub []byte, cipher Cipher, localUSO bool, laneCount byte, req AssignmentRequest) (laneIdentity, error) {
	c.SetDeadline(time.Now().Add(hsTimeout))
	defer c.SetDeadline(time.Time{})

	obfsKey := obfsKeyFromServerPub(serverPub)
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   noiseSuite(cipher),
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		Prologue:      hsPrologue,
		StaticKeypair: static,
		PeerStatic:    serverPub,
	})
	if err != nil {
		return laneIdentity{}, err
	}

	msg1, _, _, err := hs.WriteMessage(nil, buildClientPayload(cipher, laneCount, req, localUSO))
	if err != nil {
		return laneIdentity{}, err
	}
	if err := writeObfMsg(c, obfsKey, msg1); err != nil {
		return laneIdentity{}, err
	}

	rawMsg2, err := readObfMsg(c, obfsKey)
	if err != nil {
		return laneIdentity{}, err
	}
	payload2, csTx, csRx, err := hs.ReadMessage(nil, rawMsg2)
	if err != nil {
		return laneIdentity{}, fmt.Errorf("handshake: server auth failed: %w", err)
	}
	asg, serverUSO, err := parseServerPayload(payload2)
	if err != nil {
		return laneIdentity{}, err
	}

	// ReadMessage returns (init->resp, resp->init). The client sends on
	// the first and receives on the second.
	return laneIdentity{
		keys:       laneKeys{encrypted: true, kind: cipher, tx: transportKey(cipher, csTx), rx: transportKey(cipher, csRx)},
		clientID:   deriveClientID(static.Public),
		pubKey:     static.Public,
		laneCount:  laneCount,
		usoEnabled: localUSO && serverUSO,
		assigned4:  asg.V4Addr,
		prefix4:    asg.V4Prefix,
		peer4:      asg.V4Peer,
		assigned6:  asg.V6Addr,
		prefix6:    asg.V6Prefix,
		peer6:      asg.V6Peer,
	}, nil
}

// acceptHandshake runs the server (Noise responder) side. static is the
// server's own static keypair; cipher must match what clients use (the
// suite is not negotiated in-band). authorize vets the client's static
// public key before assignFn allocates an address.
func acceptHandshake(c net.Conn, static noise.DHKey, cipher Cipher, localUSO bool, authorize pubKeyAuthorizer, assignFn acceptAssignFunc) (laneIdentity, error) {
	c.SetDeadline(time.Now().Add(hsTimeout))
	defer c.SetDeadline(time.Time{})

	obfsKey := obfsKeyFromServerPub(static.Public)
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   noiseSuite(cipher),
		Pattern:       noise.HandshakeIK,
		Initiator:     false,
		Prologue:      hsPrologue,
		StaticKeypair: static,
	})
	if err != nil {
		return laneIdentity{}, err
	}

	rawMsg1, err := readObfMsg(c, obfsKey)
	if err != nil {
		return laneIdentity{}, err
	}
	payload1, _, _, err := hs.ReadMessage(nil, rawMsg1)
	if err != nil {
		// Bad envelope key, wrong cipher suite, or a client that does not
		// hold a valid static key: rejected before any client identity is
		// established, so nothing was allocated.
		return laneIdentity{}, fmt.Errorf("handshake: client auth failed: %w", err)
	}
	clientPub := append([]byte(nil), hs.PeerStatic()...)
	clientID := deriveClientID(clientPub)

	// From here the client_id is known; surface it on error so the caller
	// can release any allocation made below.
	fail := func(err error) (laneIdentity, error) {
		return laneIdentity{clientID: clientID, pubKey: clientPub}, err
	}

	userName, err := authorize(clientPub)
	if err != nil {
		return fail(err)
	}
	pCipher, laneCount, req, clientUSO, err := parseClientPayload(payload1)
	if err != nil {
		return fail(err)
	}
	if pCipher != cipher {
		return fail(fmt.Errorf("handshake: cipher mismatch (client %s, server %s)", pCipher, cipher))
	}

	var asg AssignmentResponse
	if assignFn != nil {
		if asg, err = assignFn(userName, clientID, req); err != nil {
			return fail(err)
		}
	}

	msg2, csRx, csTx, err := hs.WriteMessage(nil, buildServerPayload(asg, localUSO))
	if err != nil {
		return fail(err)
	}
	if err := writeObfMsg(c, obfsKey, msg2); err != nil {
		return fail(err)
	}

	// WriteMessage returns (init->resp, resp->init). The server receives
	// on the first and sends on the second.
	return laneIdentity{
		keys:       laneKeys{encrypted: true, kind: cipher, tx: transportKey(cipher, csTx), rx: transportKey(cipher, csRx)},
		clientID:   clientID,
		pubKey:     clientPub,
		laneCount:  laneCount,
		userName:   userName,
		usoEnabled: localUSO && clientUSO,
		assigned4:  asg.V4Addr,
		prefix4:    asg.V4Prefix,
		peer4:      asg.V4Peer,
		assigned6:  asg.V6Addr,
		prefix6:    asg.V6Prefix,
		peer6:      asg.V6Peer,
	}, nil
}

func zeroAddrV4() netip.Addr {
	return netip.AddrFrom4([4]byte{})
}
