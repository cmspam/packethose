package packethose

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
)

// userDBHolder lets the authorized-client set be swapped at runtime (hot
// reload) without restarting the server. The get/set pair is lock-free.
// A nil holder, or one holding a nil DB, behaves as an empty database.
type userDBHolder struct{ p atomic.Pointer[UserDB] }

func newUserDBHolder(db *UserDB) *userDBHolder {
	h := &userDBHolder{}
	h.p.Store(db)
	return h
}

func (h *userDBHolder) get() *UserDB {
	if h == nil {
		return nil
	}
	return h.p.Load()
}

func (h *userDBHolder) set(db *UserDB) {
	if h != nil {
		h.p.Store(db)
	}
}

// User describes one configured tunnel identity. Identity is the
// client's X25519 static public key; Name is a human-readable label used
// for quota and logging only.
type User struct {
	Name          string
	PublicKey     []byte // 32-byte X25519 static public key
	MaxConcurrent int
	Reserved      []netip.Addr
}

// UserDB holds the server's authorized clients and tracks concurrent
// session counts for per-user quota. Authorization is an O(1) lookup on
// the client's static public key; there is no secret to brute-force.
type UserDB struct {
	mu     sync.Mutex
	byKey  map[string]*userEntry // key = string(32-byte pubkey)
	byName map[string]*userEntry
	resV4  map[netip.Addr]string
	resV6  map[netip.Addr]string
}

type userEntry struct {
	u      User
	active int
}

// NewUserDB constructs and validates a UserDB.
func NewUserDB(users []User) (*UserDB, error) {
	db := &UserDB{
		byKey:  make(map[string]*userEntry, len(users)),
		byName: make(map[string]*userEntry, len(users)),
		resV4:  make(map[netip.Addr]string),
		resV6:  make(map[netip.Addr]string),
	}
	for i := range users {
		u := users[i]
		if u.Name == "" {
			return nil, fmt.Errorf("user index %d: name is required", i)
		}
		if len(u.PublicKey) != pubKeyLen {
			return nil, fmt.Errorf("user %q: public key must be %d bytes", u.Name, pubKeyLen)
		}
		if u.MaxConcurrent < 0 {
			return nil, fmt.Errorf("user %q: max_concurrent cannot be negative", u.Name)
		}
		if _, ok := db.byName[u.Name]; ok {
			return nil, fmt.Errorf("user %q: duplicate name", u.Name)
		}
		if _, ok := db.byKey[string(u.PublicKey)]; ok {
			return nil, fmt.Errorf("user %q: duplicate public key", u.Name)
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
		e := &userEntry{u: u}
		db.byKey[string(u.PublicKey)] = e
		db.byName[u.Name] = e
	}
	return db, nil
}

// Empty reports whether the database has no users configured.
func (db *UserDB) Empty() bool { return len(db.byKey) == 0 }

// LookupByKey returns the user whose static public key matches, or nil.
func (db *UserDB) LookupByKey(pub []byte) *User {
	if db == nil {
		return nil
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	e, ok := db.byKey[string(pub)]
	if !ok {
		return nil
	}
	u := e.u
	return &u
}

// AcquireSlot reserves one concurrent slot for the named user.
func (db *UserDB) AcquireSlot(name string) error {
	if db == nil {
		return ErrUnknownUser
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	e, ok := db.byName[name]
	if !ok {
		return ErrUnknownUser
	}
	if e.u.MaxConcurrent > 0 && e.active >= e.u.MaxConcurrent {
		return ErrQuotaExceeded
	}
	e.active++
	return nil
}

// ReleaseSlot drops one concurrent slot for the named user.
func (db *UserDB) ReleaseSlot(name string) {
	if db == nil {
		return
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	if e, ok := db.byName[name]; ok && e.active > 0 {
		e.active--
	}
}

// ReservationOwner reports which user, if any, reserves the address.
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

// ReservedFor returns the configured reservation addresses for a user.
func (db *UserDB) ReservedFor(name string) []netip.Addr {
	if db == nil {
		return nil
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	if e, ok := db.byName[name]; ok {
		return e.u.Reserved
	}
	return nil
}

// AllReservations returns the union of reserved addresses across users.
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

// ErrUnknownUser is returned when a handshake presents a public key not
// in the database.
var ErrUnknownUser = errors.New("packethose: unknown client key")

// ErrQuotaExceeded is returned when a user has reached MaxConcurrent.
var ErrQuotaExceeded = errors.New("packethose: user quota exceeded")

// ParseKey decodes a 32-byte X25519 key from base64 (WireGuard-style) or
// hex. Empty input returns nil with no error.
func ParseKey(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == pubKeyLen {
		return b, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("key: not valid base64 or hex: %w", err)
	}
	if len(b) != pubKeyLen {
		return nil, fmt.Errorf("key: must be %d bytes, got %d", pubKeyLen, len(b))
	}
	return b, nil
}

// FormatKey renders a key as base64, the canonical on-disk form.
func FormatKey(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
