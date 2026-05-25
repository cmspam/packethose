package packethose

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

// userNameLen is the on-wire length of the per-handshake username
// field. Names are NUL-padded and case-sensitive.
const userNameLen = 16

// User describes one configured tunnel identity.
type User struct {
	Name          string
	PSK           []byte
	MaxConcurrent int
	Reserved      []netip.Addr
}

// UserDB holds the server's configured users and tracks concurrent
// session counts for per-user quota enforcement. Lookup is O(1) on
// the on-wire name; brute-force PSK matching is never used.
type UserDB struct {
	mu     sync.Mutex
	byName map[[userNameLen]byte]*userEntry
	resV4  map[netip.Addr]string
	resV6  map[netip.Addr]string
}

type userEntry struct {
	u      User
	wire   [userNameLen]byte
	active int
}

// NewUserDB constructs a UserDB and validates the input. Empty user
// lists return a non-nil UserDB so the legacy single-PSK fallback can
// still be selected by the caller.
func NewUserDB(users []User) (*UserDB, error) {
	db := &UserDB{
		byName: make(map[[userNameLen]byte]*userEntry, len(users)),
		resV4:  make(map[netip.Addr]string),
		resV6:  make(map[netip.Addr]string),
	}
	for i := range users {
		u := users[i]
		if u.Name == "" {
			return nil, fmt.Errorf("user index %d: name is required", i)
		}
		if len(u.Name) > userNameLen {
			return nil, fmt.Errorf("user %q: name longer than %d bytes", u.Name, userNameLen)
		}
		if len(u.PSK) < 16 {
			return nil, fmt.Errorf("user %q: psk must be at least 16 bytes", u.Name)
		}
		if u.MaxConcurrent < 0 {
			return nil, fmt.Errorf("user %q: max_concurrent cannot be negative", u.Name)
		}
		var wire [userNameLen]byte
		copy(wire[:], u.Name)
		if _, ok := db.byName[wire]; ok {
			return nil, fmt.Errorf("user %q: duplicate name", u.Name)
		}
		for _, r := range u.Reserved {
			if !r.IsValid() {
				return nil, fmt.Errorf("user %q: invalid reserved address", u.Name)
			}
			if r.Is4() {
				if other, ok := db.resV4[r]; ok && other != u.Name {
					return nil, fmt.Errorf("reservation conflict: %s claimed by both %q and %q", r, other, u.Name)
				}
				db.resV4[r] = u.Name
			} else {
				if other, ok := db.resV6[r]; ok && other != u.Name {
					return nil, fmt.Errorf("reservation conflict: %s claimed by both %q and %q", r, other, u.Name)
				}
				db.resV6[r] = u.Name
			}
		}
		db.byName[wire] = &userEntry{u: u, wire: wire}
	}
	return db, nil
}

// Empty reports whether the database has no users configured.
func (db *UserDB) Empty() bool { return len(db.byName) == 0 }

// Lookup returns the user matching the on-wire name field, or nil if
// no such user exists.
func (db *UserDB) Lookup(wire [userNameLen]byte) *User {
	if db == nil {
		return nil
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	e, ok := db.byName[wire]
	if !ok {
		return nil
	}
	u := e.u
	return &u
}

// AcquireSlot reserves one concurrent slot for the named user. It
// returns ErrQuotaExceeded when MaxConcurrent would be exceeded, or
// ErrUnknownUser when the name is not in the database.
func (db *UserDB) AcquireSlot(name string) error {
	if db == nil {
		return ErrUnknownUser
	}
	var wire [userNameLen]byte
	copy(wire[:], name)
	db.mu.Lock()
	defer db.mu.Unlock()
	e, ok := db.byName[wire]
	if !ok {
		return ErrUnknownUser
	}
	if e.u.MaxConcurrent > 0 && e.active >= e.u.MaxConcurrent {
		return ErrQuotaExceeded
	}
	e.active++
	return nil
}

// ReleaseSlot drops one concurrent slot for the named user. Calling
// Release without a matching Acquire is a no-op.
func (db *UserDB) ReleaseSlot(name string) {
	if db == nil {
		return
	}
	var wire [userNameLen]byte
	copy(wire[:], name)
	db.mu.Lock()
	defer db.mu.Unlock()
	if e, ok := db.byName[wire]; ok && e.active > 0 {
		e.active--
	}
}

// ReservationOwner reports which user, if any, has the given address
// listed as a reservation. The empty string means unreserved.
func (db *UserDB) ReservationOwner(a netip.Addr) string {
	if db == nil || !a.IsValid() {
		return ""
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	if a.Is4() {
		return db.resV4[a]
	}
	return db.resV6[a]
}

// ReservedFor returns the configured reservation addresses for a
// user. The returned slice must not be mutated.
func (db *UserDB) ReservedFor(name string) []netip.Addr {
	if db == nil {
		return nil
	}
	var wire [userNameLen]byte
	copy(wire[:], name)
	db.mu.Lock()
	defer db.mu.Unlock()
	if e, ok := db.byName[wire]; ok {
		return e.u.Reserved
	}
	return nil
}

// AllReservations returns the union of reserved IPv4 and IPv6
// addresses across all users, regardless of owner. Useful for pool
// allocators that need to skip every reserved slot.
func (db *UserDB) AllReservations() (v4, v6 []netip.Addr) {
	if db == nil {
		return nil, nil
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	v4 = make([]netip.Addr, 0, len(db.resV4))
	for a := range db.resV4 {
		v4 = append(v4, a)
	}
	v6 = make([]netip.Addr, 0, len(db.resV6))
	for a := range db.resV6 {
		v6 = append(v6, a)
	}
	return v4, v6
}

// ErrUnknownUser is returned when a handshake names a user not in the
// database.
var ErrUnknownUser = errors.New("packethose: unknown user")

// ErrQuotaExceeded is returned when a user has reached MaxConcurrent
// active sessions.
var ErrQuotaExceeded = errors.New("packethose: user quota exceeded")

// ParsePSKHex decodes a hex PSK string and enforces the 16-byte
// minimum used elsewhere in the codebase.
func ParsePSKHex(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("psk hex: %w", err)
	}
	if len(b) < 16 {
		return nil, fmt.Errorf("psk: must be at least 16 bytes")
	}
	return b, nil
}

// encodeUserName produces the 16-byte on-wire form of a username.
// Longer names are truncated; shorter ones are NUL-padded.
func encodeUserName(name string) [userNameLen]byte {
	var w [userNameLen]byte
	copy(w[:], name)
	return w
}

// decodeUserName returns the printable portion of an on-wire name
// (everything before the first NUL).
func decodeUserName(w [userNameLen]byte) string {
	if i := bytes.IndexByte(w[:], 0); i >= 0 {
		return string(w[:i])
	}
	return string(w[:])
}
