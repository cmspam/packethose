//go:build linux

package packethose

import (
	"bytes"
	"log"
	"net/netip"
	"strings"
	"testing"
)

// TestNFTBuildScript exercises the deterministic ruleset rendering
// without needing root or the nft binary. The installer's buildScript
// is unexported but reachable on the value.
func TestNFTBuildScript(t *testing.T) {
	logger := log.New(&bytes.Buffer{}, "", 0)
	cfg := NFTConfig{
		Enabled:    true,
		Family:     "inet",
		TableName:  "packethose",
		TUNMatch:   "phose-*",
		Isolation:  true,
		Masquerade: true,
		TPROXY:     true,
		TPROXYPort: 13338,
		TPROXYMark: 0x1,
		RouteTable: 13338,
		IPv4:       true,
		IPv6:       true,
	}
	// NewNFTInstaller verifies the nft binary exists. Substitute a
	// no-op nft path so the test runs in CI containers without it.
	saved := nftBin
	nftBin = "/bin/true"
	defer func() { nftBin = saved }()
	ni, err := NewNFTInstaller(cfg, logger)
	if err != nil {
		t.Fatalf("NewNFTInstaller: %v", err)
	}
	s := ni.buildScript()
	for _, want := range []string{
		`table inet packethose {`,
		`chain prerouting {`,
		`iifname "phose-*" meta l4proto { tcp, udp } tproxy ip to :13338`,
		`iifname "phose-*" meta l4proto { tcp, udp } tproxy ip6 to :13338`,
		`chain forward {`,
		`iifname "phose-*" oifname "phose-*" drop`,
		`chain postrouting {`,
		`oifname != "phose-*" masquerade`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script missing %q\nscript:\n%s", want, s)
		}
	}
}

// TestNFTServerIPExempt verifies the prerouting chain accepts traffic
// destined to the server's own tunnel IPs before the tproxy redirect.
// Without this, an iperf3 -s -B 10.66.0.1 would be intercepted by the
// tproxy listener and either fail (isolation enforced) or loop back
// through a needless userspace splice.
func TestNFTServerIPExempt(t *testing.T) {
	logger := log.New(&bytes.Buffer{}, "", 0)
	cfg := NFTConfig{
		Enabled:    true,
		Family:     "inet",
		TableName:  "packethose",
		TUNMatch:   "phose-*",
		TPROXY:     true,
		TPROXYPort: 13338,
		TPROXYMark: 0x1,
		RouteTable: 13338,
		IPv4:       true,
		IPv6:       true,
		ServerIP4:  netip.MustParseAddr("10.66.0.1"),
		ServerIP6:  netip.MustParseAddr("fd00:66::1"),
	}
	saved := nftBin
	nftBin = "/bin/true"
	defer func() { nftBin = saved }()
	ni, err := NewNFTInstaller(cfg, logger)
	if err != nil {
		t.Fatalf("NewNFTInstaller: %v", err)
	}
	s := ni.buildScript()

	// Accept rules must appear AND must come before the tproxy
	// redirect (else the redirect catches the packet first).
	acceptV4 := `iifname "phose-*" ip daddr 10.66.0.1 accept`
	acceptV6 := `iifname "phose-*" ip6 daddr fd00:66::1 accept`
	redirectV4 := `tproxy ip to :13338`
	if !strings.Contains(s, acceptV4) {
		t.Errorf("script missing v4 accept rule %q\nscript:\n%s", acceptV4, s)
	}
	if !strings.Contains(s, acceptV6) {
		t.Errorf("script missing v6 accept rule %q\nscript:\n%s", acceptV6, s)
	}
	if strings.Index(s, acceptV4) > strings.Index(s, redirectV4) {
		t.Errorf("v4 accept rule appears AFTER tproxy redirect; redirect would catch first")
	}
}

func TestInPoolExemptsServerIP(t *testing.T) {
	cfg := TPROXYConfig{
		PoolV4:    netip.MustParsePrefix("10.66.0.0/24"),
		PoolV6:    netip.MustParsePrefix("fd00:66::/64"),
		ServerIP4: netip.MustParseAddr("10.66.0.1"),
		ServerIP6: netip.MustParseAddr("fd00:66::1"),
	}
	l := &TPROXYListener{cfg: cfg}
	// Server's own IPs are in pool but must be exempted.
	if l.inPool(netip.MustParseAddr("10.66.0.1")) {
		t.Errorf("server v4 IP should be exempt from inPool")
	}
	if l.inPool(netip.MustParseAddr("fd00:66::1")) {
		t.Errorf("server v6 IP should be exempt from inPool")
	}
	// Other pool IPs (clients) are still in pool.
	if !l.inPool(netip.MustParseAddr("10.66.0.10")) {
		t.Errorf("client v4 IP should be in pool")
	}
	if !l.inPool(netip.MustParseAddr("fd00:66::10")) {
		t.Errorf("client v6 IP should be in pool")
	}
	// Public IPs are not in pool.
	if l.inPool(netip.MustParseAddr("1.1.1.1")) {
		t.Errorf("public v4 IP should not be in pool")
	}
}

func TestNFTDisabledIsNoop(t *testing.T) {
	logger := log.New(&bytes.Buffer{}, "", 0)
	ni, err := NewNFTInstaller(NFTConfig{Enabled: false}, logger)
	if err != nil {
		t.Fatalf("NewNFTInstaller: %v", err)
	}
	if ni.Enabled() {
		t.Fatalf("expected Enabled() = false")
	}
	if err := ni.Install(); err != nil {
		t.Fatalf("Install on disabled should be nil, got %v", err)
	}
	if err := ni.Remove(); err != nil {
		t.Fatalf("Remove on disabled should be nil, got %v", err)
	}
	if err := ni.Reconcile(); err != nil {
		t.Fatalf("Reconcile on disabled should be nil, got %v", err)
	}
}
