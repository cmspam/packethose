package packethose

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"
)

type hsResult struct {
	id  laneIdentity
	err error
}

func genKeyT(t *testing.T) (priv, pub []byte) {
	t.Helper()
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	return priv, pub
}

// runHandshake drives a full v7 Noise IK handshake over net.Pipe and
// returns both sides' identities.
func runHandshake(t *testing.T, serverPriv, clientPriv []byte, authorize pubKeyAuthorizer, assign acceptAssignFunc, cipher Cipher, req AssignmentRequest) (cli, srv laneIdentity) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })

	serverStatic, err := noiseStatic(serverPriv)
	if err != nil {
		t.Fatalf("server static: %v", err)
	}
	clientStatic, err := noiseStatic(clientPriv)
	if err != nil {
		t.Fatalf("client static: %v", err)
	}

	sc := make(chan hsResult, 1)
	go func() {
		id, err := acceptHandshake(b, serverStatic, cipher, false, authorize, assign)
		sc <- hsResult{id, err}
	}()
	a.SetDeadline(time.Now().Add(2 * time.Second))
	cli, err = initiateHandshake(a, clientStatic, serverStatic.Public, cipher, false, 4, req)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	r := <-sc
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}
	return cli, r.id
}

func assignFixedV4() acceptAssignFunc {
	return func(name string, id [clientIDLen]byte, r AssignmentRequest) (AssignmentResponse, error) {
		return AssignmentResponse{
			V4Addr:   netip.MustParseAddr("10.66.0.10"),
			V4Prefix: 24,
			V4Peer:   netip.MustParseAddr("10.66.0.1"),
		}, nil
	}
}

// TestHandshakeRoundtripSinglePeer exercises single-peer mode: the server
// authorizes one client static public key.
func TestHandshakeRoundtripSinglePeer(t *testing.T) {
	serverPriv, _ := genKeyT(t)
	clientPriv, clientPub := genKeyT(t)
	authorize := serverAuthorizer(nil, clientPub)

	cli, srv := runHandshake(t, serverPriv, clientPriv, authorize, assignFixedV4(), CipherAESGCM,
		AssignmentRequest{V4: netip.MustParseAddr("10.66.0.10")})

	if cli.assigned4.String() != "10.66.0.10" {
		t.Fatalf("bad assignment: %v", cli.assigned4)
	}
	if !bytes.Equal(srv.pubKey, clientPub) {
		t.Fatalf("server saw wrong client pubkey")
	}
	assertKeysAgree(t, cli, srv)
}

// TestHandshakeRoundtripUserDB exercises multi-client mode: clients are
// authorized by static public key against the user DB.
func TestHandshakeRoundtripUserDB(t *testing.T) {
	serverPriv, _ := genKeyT(t)
	alicePriv, alicePub := genKeyT(t)
	_, bobPub := genKeyT(t)
	db, err := NewUserDB([]User{
		{Name: "alice", PublicKey: alicePub, MaxConcurrent: 2},
		{Name: "bob", PublicKey: bobPub},
	})
	if err != nil {
		t.Fatalf("NewUserDB: %v", err)
	}

	assign := func(name string, id [clientIDLen]byte, r AssignmentRequest) (AssignmentResponse, error) {
		if name != "alice" {
			t.Errorf("expected user alice, got %q", name)
		}
		return AssignmentResponse{V4Addr: netip.MustParseAddr("10.66.0.10"), V4Prefix: 24}, nil
	}
	cli, srv := runHandshake(t, serverPriv, alicePriv, serverAuthorizer(db, nil), assign, CipherChaCha, AssignmentRequest{})
	if srv.userName != "alice" {
		t.Fatalf("expected userName alice, got %q", srv.userName)
	}
	assertKeysAgree(t, cli, srv)
}

// TestHandshakeForwardSecrecy verifies two handshakes between the same
// identities derive different transport keys (the ephemeral DH).
func TestHandshakeForwardSecrecy(t *testing.T) {
	serverPriv, _ := genKeyT(t)
	clientPriv, clientPub := genKeyT(t)
	auth := serverAuthorizer(nil, clientPub)
	cli1, _ := runHandshake(t, serverPriv, clientPriv, auth, nil, CipherAESGCM, AssignmentRequest{})
	cli2, _ := runHandshake(t, serverPriv, clientPriv, auth, nil, CipherAESGCM, AssignmentRequest{})

	if bytes.Equal(cli1.keys.tx, cli2.keys.tx) || bytes.Equal(cli1.keys.rx, cli2.keys.rx) {
		t.Fatal("transport keys repeated across handshakes; ephemeral DH not in effect")
	}
}

// TestHandshakeWrongServerKey: a client that targets the wrong server
// public key cannot complete the handshake.
func TestHandshakeWrongServerKey(t *testing.T) {
	defer shortHandshakeTimeout()()
	serverPriv, _ := genKeyT(t)
	clientPriv, clientPub := genKeyT(t)
	_, wrongServerPub := genKeyT(t)

	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	serverStatic, _ := noiseStatic(serverPriv)
	clientStatic, _ := noiseStatic(clientPriv)

	sc := make(chan error, 1)
	go func() {
		_, err := acceptHandshake(b, serverStatic, CipherAESGCM, false, serverAuthorizer(nil, clientPub), nil)
		sc <- err
	}()
	go func() {
		_, _ = initiateHandshake(a, clientStatic, wrongServerPub, CipherAESGCM, false, 1, AssignmentRequest{})
		a.Close()
	}()
	if err := <-sc; err == nil {
		t.Fatal("expected server to reject a client using the wrong server key")
	}
}

// TestHandshakeUnknownClient: an unauthorized client key is rejected.
func TestHandshakeUnknownClient(t *testing.T) {
	defer shortHandshakeTimeout()()
	serverPriv, _ := genKeyT(t)
	clientPriv, _ := genKeyT(t)
	_, otherPub := genKeyT(t) // the only authorized key, which the client does not hold

	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	serverStatic, _ := noiseStatic(serverPriv)
	clientStatic, _ := noiseStatic(clientPriv)

	sc := make(chan error, 1)
	go func() {
		_, err := acceptHandshake(b, serverStatic, CipherAESGCM, false, serverAuthorizer(nil, otherPub), assignFixedV4())
		sc <- err
	}()
	go func() {
		_, _ = initiateHandshake(a, clientStatic, serverStatic.Public, CipherAESGCM, false, 1, AssignmentRequest{})
		a.Close()
	}()
	if err := <-sc; err == nil {
		t.Fatal("expected server to reject an unauthorized client key")
	}
}

func assertKeysAgree(t *testing.T, cli, srv laneIdentity) {
	t.Helper()
	if len(cli.keys.tx) == 0 {
		t.Fatal("empty transport key")
	}
	if !bytes.Equal(cli.keys.tx, srv.keys.rx) {
		t.Fatal("client tx key != server rx key")
	}
	if !bytes.Equal(cli.keys.rx, srv.keys.tx) {
		t.Fatal("client rx key != server tx key")
	}
}

// shortHandshakeTimeout lowers the handshake deadline for negative tests
// that would otherwise wait out the full production timeout.
func shortHandshakeTimeout() func() {
	old := hsTimeout
	hsTimeout = 200 * time.Millisecond
	return func() { hsTimeout = old }
}

func bytesPattern(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}
