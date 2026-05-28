package packethose

import (
	"net/netip"
	"testing"
)

// testPub returns a distinct 32-byte public key for tests, tagged by id.
func testPub(id byte) []byte {
	k := bytesPattern(pubKeyLen)
	k[0] = id
	return k
}

func TestUserDBLookupAndQuota(t *testing.T) {
	alicePub := testPub(0xaa)
	bobPub := testPub(0xbb)
	users := []User{
		{Name: "alice", PublicKey: alicePub, MaxConcurrent: 2},
		{Name: "bob", PublicKey: bobPub, MaxConcurrent: 0},
	}
	db, err := NewUserDB(users)
	if err != nil {
		t.Fatalf("NewUserDB: %v", err)
	}
	if u := db.LookupByKey(alicePub); u == nil || u.Name != "alice" {
		t.Fatalf("alice lookup failed: %#v", u)
	}
	if u := db.LookupByKey(testPub(0x99)); u != nil {
		t.Fatalf("expected nil for unknown key, got %#v", u)
	}
	if err := db.AcquireSlot("alice"); err != nil {
		t.Fatalf("acquire 1: %v", err)
	}
	if err := db.AcquireSlot("alice"); err != nil {
		t.Fatalf("acquire 2: %v", err)
	}
	if err := db.AcquireSlot("alice"); err != ErrQuotaExceeded {
		t.Fatalf("expected quota, got %v", err)
	}
	db.ReleaseSlot("alice")
	if err := db.AcquireSlot("alice"); err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	if err := db.AcquireSlot("bob"); err != nil {
		t.Fatalf("bob unlimited: %v", err)
	}
}

func TestUserDBReservationConflict(t *testing.T) {
	a := netip.MustParseAddr("10.66.0.5")
	users := []User{
		{Name: "alice", PublicKey: testPub(0xaa), Reserved: []netip.Addr{a}},
		{Name: "bob", PublicKey: testPub(0xbb), Reserved: []netip.Addr{a}},
	}
	if _, err := NewUserDB(users); err == nil {
		t.Fatalf("expected reservation conflict error")
	}
}

func TestUserDBDuplicateKey(t *testing.T) {
	users := []User{
		{Name: "alice", PublicKey: testPub(0xaa)},
		{Name: "bob", PublicKey: testPub(0xaa)},
	}
	if _, err := NewUserDB(users); err == nil {
		t.Fatalf("expected duplicate public key error")
	}
}

func TestIPPoolReservedForOwner(t *testing.T) {
	subnet := netip.MustParsePrefix("10.66.0.0/24")
	reserved := netip.MustParseAddr("10.66.0.5")
	users := []User{
		{Name: "alice", PublicKey: testPub(0xaa), Reserved: []netip.Addr{reserved}},
		{Name: "bob", PublicKey: testPub(0xbb)},
	}
	db, err := NewUserDB(users)
	if err != nil {
		t.Fatalf("NewUserDB: %v", err)
	}
	v4Res, _ := db.AllReservations()
	pool, err := newIPPool(subnet, append([]netip.Addr{netip.MustParseAddr("10.66.0.1")}, v4Res...)...)
	if err != nil {
		t.Fatalf("newIPPool: %v", err)
	}
	var bobID [clientIDLen]byte
	bobID[0] = 0xbb
	got, err := pool.AllocateFor("bob", bobID, reserved, db)
	if err != nil {
		t.Fatalf("alloc bob: %v", err)
	}
	if got == reserved {
		t.Fatalf("bob should not receive alice's reservation %s", reserved)
	}

	var aliceID [clientIDLen]byte
	aliceID[0] = 0xaa
	got, err = pool.AllocateFor("alice", aliceID, netip.Addr{}, db)
	if err != nil {
		t.Fatalf("alloc alice: %v", err)
	}
	if got != reserved {
		t.Fatalf("alice should receive her reservation %s, got %s", reserved, got)
	}
}
