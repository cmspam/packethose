//go:build linux

package packethose

import (
	"bytes"
	"log"
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
