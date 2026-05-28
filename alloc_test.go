package packethose

import (
	"net"
	"net/netip"
	"testing"
)

// TestNoAllocationOnAuthFailure proves allocation is gated behind
// authentication: a client whose static key is not authorized is
// rejected before assignFn runs, so it cannot drive an allocation.
func TestNoAllocationOnAuthFailure(t *testing.T) {
	defer shortHandshakeTimeout()()
	serverPriv, _ := genKeyT(t)
	clientPriv, _ := genKeyT(t)
	_, authorizedPub := genKeyT(t) // a different key is the only authorized one

	allocated := false
	assign := func(name string, id [clientIDLen]byte, r AssignmentRequest) (AssignmentResponse, error) {
		allocated = true
		return AssignmentResponse{V4Addr: netip.MustParseAddr("10.66.0.10"), V4Prefix: 24}, nil
	}

	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	serverStatic, _ := noiseStatic(serverPriv)
	clientStatic, _ := noiseStatic(clientPriv)

	sc := make(chan error, 1)
	go func() {
		_, err := acceptHandshake(b, serverStatic, CipherAESGCM, false, serverAuthorizer(nil, authorizedPub), assign)
		sc <- err
	}()
	go func() {
		_, _ = initiateHandshake(a, clientStatic, serverStatic.Public, CipherAESGCM, false, 1, AssignmentRequest{})
		a.Close()
	}()

	if err := <-sc; err == nil {
		t.Fatal("expected rejection for unauthorized client key")
	}
	if allocated {
		t.Fatal("assignFn ran despite failed authentication: pre-auth allocation leak")
	}
}

// TestIPPoolClaimProtectsAfterRelease verifies the multi-lane race fix.
func TestIPPoolClaimProtectsAfterRelease(t *testing.T) {
	p, err := newIPPool(netip.MustParsePrefix("10.66.0.0/24"))
	if err != nil {
		t.Fatalf("newIPPool: %v", err)
	}
	var id1 [clientIDLen]byte
	id1[0] = 1
	addr, err := p.Allocate(id1, netip.Addr{})
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	p.Release(id1)
	p.Claim(id1, addr)

	var id2 [clientIDLen]byte
	id2[0] = 2
	got, err := p.Allocate(id2, addr)
	if err != nil {
		t.Fatalf("allocate id2: %v", err)
	}
	if got == addr {
		t.Fatalf("Claim failed to protect %v; handed to another client", addr)
	}
}

// TestIPPoolReleaseFreesForReuse confirms a released address can be
// handed out again (the orphan-reclamation path).
func TestIPPoolReleaseFreesForReuse(t *testing.T) {
	p, err := newIPPool(netip.MustParsePrefix("10.66.0.0/30"))
	if err != nil {
		t.Fatalf("newIPPool: %v", err)
	}
	var id1 [clientIDLen]byte
	id1[0] = 1
	a1, err := p.Allocate(id1, netip.Addr{})
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	p.Release(id1)

	var id2 [clientIDLen]byte
	id2[0] = 2
	if _, err := p.Allocate(id2, netip.Addr{}); err != nil {
		t.Fatalf("allocate after release: %v", err)
	}
	_ = a1
}
