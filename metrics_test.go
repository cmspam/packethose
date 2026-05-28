package packethose

import (
	"bytes"
	"io"
	"log"
	"strings"
	"testing"
)

func TestMetricsExposition(t *testing.T) {
	m := NewMetrics()
	m.incAccept()
	m.incHandshakeOK()
	m.incHandshakeFail()
	m.incRateLimited()
	m.incSlotsFull()
	m.incSessionOpened()
	m.incSessionOpened()
	m.incSessionClosed()
	m.SetStatProvider(func() []ByteStat {
		return []ByteStat{{Addr: "10.66.0.10", TxBytes: 100, RxBytes: 200}}
	})

	var buf bytes.Buffer
	m.WritePrometheus(&buf)
	out := buf.String()
	for _, want := range []string{
		"packethose_accepts_total 1",
		`packethose_handshakes_total{result="ok"} 1`,
		`packethose_handshakes_total{result="fail"} 1`,
		"packethose_rate_limited_total 1",
		"packethose_handshake_slots_exhausted_total 1",
		"packethose_sessions_active 1", // 2 opened - 1 closed
		`packethose_client_tx_bytes{addr="10.66.0.10"} 100`,
		`packethose_client_rx_bytes{addr="10.66.0.10"} 200`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q\n---\n%s", want, out)
		}
	}
}

func TestMetricsNilSafe(t *testing.T) {
	var m *Metrics // nil
	m.incAccept()
	m.incHandshakeOK()
	m.incSessionClosed()
	var buf bytes.Buffer
	m.WritePrometheus(&buf) // must not panic and must write nothing
	if buf.Len() != 0 {
		t.Fatal("nil metrics should write nothing")
	}
}

func TestServerReloadUsers(t *testing.T) {
	db0, err := NewUserDB([]User{{Name: "alice", PublicKey: testPub(0xaa)}})
	if err != nil {
		t.Fatalf("NewUserDB: %v", err)
	}
	s := &Server{logger: log.New(io.Discard, "", 0), userDB: newUserDBHolder(db0)}

	if s.userDB.get().LookupByKey(testPub(0xaa)) == nil {
		t.Fatal("alice should be present initially")
	}
	if err := s.ReloadUsers([]User{{Name: "bob", PublicKey: testPub(0xbb)}}); err != nil {
		t.Fatalf("ReloadUsers: %v", err)
	}
	if s.userDB.get().LookupByKey(testPub(0xaa)) != nil {
		t.Fatal("alice should be gone after reload")
	}
	if s.userDB.get().LookupByKey(testPub(0xbb)) == nil {
		t.Fatal("bob should be present after reload")
	}
	// A bad set is rejected and leaves the current set intact.
	if err := s.ReloadUsers([]User{{Name: "x"}}); err == nil {
		t.Fatal("expected error reloading a user with no public key")
	}
	if s.userDB.get().LookupByKey(testPub(0xbb)) == nil {
		t.Fatal("a failed reload must not disturb the live set")
	}
}
