package packethose

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Accept-path abuse controls. None of this touches the data path: every
// check runs once, before the handshake, on connection setup only.
//
// Two independent gates:
//
//   - A per-source-IP token bucket throttles how fast one address can
//     open new connections, so a single host cannot spin the accept
//     loop or exhaust handshake CPU.
//   - A server-wide semaphore caps how many handshakes are in flight at
//     once, bounding goroutines and memory under a distributed flood.
//
// The per-IP table is bounded and self-pruning so the limiter cannot
// itself become a memory-exhaustion vector.

const (
	defaultPerIPPerSec  = 10.0
	defaultPerIPBurst   = 20
	defaultMaxInFlight  = 256
	defaultMaxIPEntries = 8192
	ipEntryTTL          = 5 * time.Minute
	ipGCInterval        = time.Minute
)

// RateLimitConfig tunes the accept-path abuse controls. The zero value
// is a sensible default posture; set Disabled to turn the limiter into
// a pass-through.
type RateLimitConfig struct {
	// PerIPPerSec is the sustained new-connection rate allowed per
	// source IP. <= 0 uses the default.
	PerIPPerSec float64
	// PerIPBurst is the per-IP token-bucket depth. <= 0 uses the default.
	PerIPBurst int
	// MaxInFlight bounds concurrent in-progress handshakes server-wide.
	// <= 0 uses the default.
	MaxInFlight int
	// MaxIPEntries bounds the per-IP limiter table. <= 0 uses the default.
	MaxIPEntries int
	// Disabled turns every check into a pass-through.
	Disabled bool
}

type ipLimiterEntry struct {
	lim  *rate.Limiter
	seen time.Time
}

// connLimiter is safe for concurrent use by multiple accept goroutines.
type connLimiter struct {
	disabled   bool
	perIPRate  rate.Limit
	perIPBurst int
	maxEntries int

	mu       sync.Mutex
	limiters map[string]*ipLimiterEntry
	lastGC   time.Time
	nowFn    func() time.Time // injectable for tests

	sem chan struct{}
}

func newConnLimiter(cfg RateLimitConfig) *connLimiter {
	if cfg.Disabled {
		return &connLimiter{disabled: true}
	}
	perSec := cfg.PerIPPerSec
	if perSec <= 0 {
		perSec = defaultPerIPPerSec
	}
	burst := cfg.PerIPBurst
	if burst <= 0 {
		burst = defaultPerIPBurst
	}
	maxInFlight := cfg.MaxInFlight
	if maxInFlight <= 0 {
		maxInFlight = defaultMaxInFlight
	}
	maxEntries := cfg.MaxIPEntries
	if maxEntries <= 0 {
		maxEntries = defaultMaxIPEntries
	}
	return &connLimiter{
		perIPRate:  rate.Limit(perSec),
		perIPBurst: burst,
		maxEntries: maxEntries,
		limiters:   make(map[string]*ipLimiterEntry),
		nowFn:      time.Now,
		sem:        make(chan struct{}, maxInFlight),
	}
}

func (l *connLimiter) now() time.Time {
	if l.nowFn != nil {
		return l.nowFn()
	}
	return time.Now()
}

// allowIP reports whether a new connection from ip may proceed under the
// per-source-IP rate. It records the access time and opportunistically
// prunes the table.
func (l *connLimiter) allowIP(ip string) bool {
	if l == nil || l.disabled {
		return true
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.lastGC) >= ipGCInterval {
		l.gcLocked(now)
	}

	e, ok := l.limiters[ip]
	if !ok {
		// Backstop against a flood of one-shot source IPs: if the table
		// is at capacity and GC freed nothing, evict the stalest entry.
		if len(l.limiters) >= l.maxEntries {
			l.evictOldestLocked()
		}
		e = &ipLimiterEntry{lim: rate.NewLimiter(l.perIPRate, l.perIPBurst)}
		l.limiters[ip] = e
	}
	e.seen = now
	return e.lim.AllowN(now, 1)
}

func (l *connLimiter) gcLocked(now time.Time) {
	for ip, e := range l.limiters {
		if now.Sub(e.seen) > ipEntryTTL {
			delete(l.limiters, ip)
		}
	}
	l.lastGC = now
}

func (l *connLimiter) evictOldestLocked() {
	var oldestIP string
	var oldest time.Time
	for ip, e := range l.limiters {
		if oldestIP == "" || e.seen.Before(oldest) {
			oldestIP, oldest = ip, e.seen
		}
	}
	if oldestIP != "" {
		delete(l.limiters, oldestIP)
	}
}

// acquireSlot takes one in-flight handshake permit. It returns a release
// function and ok=false when the server is already at MaxInFlight, in
// which case the caller must drop the connection without handshaking.
func (l *connLimiter) acquireSlot() (release func(), ok bool) {
	if l == nil || l.disabled {
		return func() {}, true
	}
	select {
	case l.sem <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-l.sem }) }, true
	default:
		return func() {}, false
	}
}
