package packethose

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestHandshakeRoundtripLegacy exercises the v5 handshake using the
// single-PSK fallback path (no users configured, client sends empty
// username).
func TestHandshakeRoundtripLegacy(t *testing.T) {
	psk := bytesPattern(32)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	t.Cleanup(func() { a.Close(); b.Close() })

	var clientID [clientIDLen]byte
	for i := range clientID {
		clientID[i] = byte(i)
	}
	req := AssignmentRequest{V4: netip.MustParseAddr("10.66.0.10")}

	serverDone := make(chan error, 1)
	go func() {
		assign := func(name string, id [clientIDLen]byte, r AssignmentRequest) (AssignmentResponse, error) {
			return AssignmentResponse{
				V4Addr:   netip.MustParseAddr("10.66.0.10"),
				V4Prefix: 24,
				V4Peer:   netip.MustParseAddr("10.66.0.1"),
			}, nil
		}
		_, err := acceptHandshake(b, singlePSKResolver(psk), assign)
		serverDone <- err
	}()

	a.SetDeadline(time.Now().Add(2 * time.Second))
	ident, err := initiateHandshake(a, psk, CipherAESGCM, "", clientID, 4, req)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	if ident.userName != "" {
		t.Fatalf("expected empty userName, got %q", ident.userName)
	}
	if ident.assigned4.String() != "10.66.0.10" {
		t.Fatalf("bad assignment: %v", ident.assigned4)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server: %v", err)
	}
}

// TestHandshakeRoundtripUserDB exercises the per-user identity path:
// the client sends a username, the server selects the matching PSK,
// the HMAC chain verifies on both sides.
func TestHandshakeRoundtripUserDB(t *testing.T) {
	alicePSK := bytesPattern(32)
	bobPSK := bytesPattern(16)
	for i := range bobPSK {
		bobPSK[i] = 0xab
	}
	db, err := NewUserDB([]User{
		{Name: "alice", PSK: alicePSK, MaxConcurrent: 2},
		{Name: "bob", PSK: bobPSK},
	})
	if err != nil {
		t.Fatalf("NewUserDB: %v", err)
	}

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	var clientID [clientIDLen]byte
	clientID[0] = 0xaa

	serverDone := make(chan error, 1)
	go func() {
		assign := func(name string, id [clientIDLen]byte, r AssignmentRequest) (AssignmentResponse, error) {
			if name != "alice" {
				t.Errorf("expected user alice, got %q", name)
			}
			return AssignmentResponse{
				V4Addr:   netip.MustParseAddr("10.66.0.10"),
				V4Prefix: 24,
				V4Peer:   netip.MustParseAddr("10.66.0.1"),
			}, nil
		}
		_, err := acceptHandshake(b, userDBResolver(db, nil), assign)
		serverDone <- err
	}()

	a.SetDeadline(time.Now().Add(2 * time.Second))
	ident, err := initiateHandshake(a, alicePSK, CipherAESGCM, "alice", clientID, 4, AssignmentRequest{})
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	if ident.userName != "alice" {
		t.Fatalf("expected userName alice, got %q", ident.userName)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server: %v", err)
	}
}

// TestHandshakeUnknownUser verifies that the server rejects a name
// that is not in the database.
func TestHandshakeUnknownUser(t *testing.T) {
	db, err := NewUserDB([]User{{Name: "alice", PSK: bytesPattern(16)}})
	if err != nil {
		t.Fatalf("NewUserDB: %v", err)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	serverDone := make(chan error, 1)
	go func() {
		_, err := acceptHandshake(b, userDBResolver(db, nil), nil)
		serverDone <- err
	}()

	a.SetDeadline(time.Now().Add(2 * time.Second))
	var clientID [clientIDLen]byte
	_, err = initiateHandshake(a, bytesPattern(16), CipherNone, "carol", clientID, 1, AssignmentRequest{})
	// client side may see EOF or HMAC mismatch depending on timing; we
	// only need the server to reject.
	_ = err
	got := <-serverDone
	if got == nil {
		t.Fatalf("expected server reject, got nil")
	}
}

func bytesPattern(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}
