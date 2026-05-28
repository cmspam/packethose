package packethose

import (
	"fmt"
	"testing"
	"time"
)

func TestConnLimiterPerIP(t *testing.T) {
	l := newConnLimiter(RateLimitConfig{PerIPPerSec: 1, PerIPBurst: 3, MaxInFlight: 10})
	now := time.Unix(1000, 0)
	l.nowFn = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if !l.allowIP("1.2.3.4") {
			t.Fatalf("burst token %d should be allowed", i)
		}
	}
	if l.allowIP("1.2.3.4") {
		t.Fatal("4th immediate request from same IP should be denied")
	}
	if !l.allowIP("5.6.7.8") {
		t.Fatal("a different IP must have its own bucket")
	}

	now = now.Add(2 * time.Second) // refill 2 tokens at 1/sec
	if !l.allowIP("1.2.3.4") || !l.allowIP("1.2.3.4") {
		t.Fatal("expected two refilled tokens after 2s")
	}
	if l.allowIP("1.2.3.4") {
		t.Fatal("third request should exceed refill")
	}
}

func TestConnLimiterInFlight(t *testing.T) {
	l := newConnLimiter(RateLimitConfig{MaxInFlight: 2})
	r1, ok := l.acquireSlot()
	if !ok {
		t.Fatal("slot 1 should be granted")
	}
	_, ok = l.acquireSlot()
	if !ok {
		t.Fatal("slot 2 should be granted")
	}
	if _, ok := l.acquireSlot(); ok {
		t.Fatal("slot 3 should be denied at MaxInFlight=2")
	}
	r1()
	r3, ok := l.acquireSlot()
	if !ok {
		t.Fatal("a slot should free after release")
	}
	r3()
	r1() // double release must be a safe no-op
}

func TestConnLimiterDisabled(t *testing.T) {
	l := newConnLimiter(RateLimitConfig{Disabled: true})
	for i := 0; i < 1000; i++ {
		if !l.allowIP("1.2.3.4") {
			t.Fatal("disabled limiter must allow everything")
		}
	}
	if _, ok := l.acquireSlot(); !ok {
		t.Fatal("disabled limiter must always grant slots")
	}
}

func TestConnLimiterTableBounded(t *testing.T) {
	l := newConnLimiter(RateLimitConfig{MaxIPEntries: 4, PerIPPerSec: 1000, PerIPBurst: 1000})
	now := time.Unix(1000, 0)
	l.nowFn = func() time.Time { return now }
	for i := 0; i < 1000; i++ {
		l.allowIP(fmt.Sprintf("10.0.%d.%d", i/256, i%256))
	}
	if len(l.limiters) > 4 {
		t.Fatalf("per-IP table grew to %d, expected <= 4", len(l.limiters))
	}
}
