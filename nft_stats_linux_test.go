//go:build linux

package packethose

import (
	"bytes"
	"log"
	"net/netip"
	"strings"
	"testing"
)

// TestNFTAccountingScript checks the per-client counter sets and the
// prerouting/postrouting accounting chains render when Accounting is on.
func TestNFTAccountingScript(t *testing.T) {
	logger := log.New(&bytes.Buffer{}, "", 0)
	cfg := NFTConfig{
		Enabled:    true,
		Family:     "inet",
		TableName:  "packethose",
		Masquerade: true,
		Accounting: true,
		IPv4:       true,
		IPv6:       true,
		PoolV4:     netip.MustParsePrefix("10.66.0.0/24"),
		PoolV6:     netip.MustParsePrefix("fd00:66::/64"),
	}
	saved := nftBin
	nftBin = "/bin/true"
	defer func() { nftBin = saved }()
	ni, err := NewNFTInstaller(cfg, logger)
	if err != nil {
		t.Fatalf("NewNFTInstaller: %v", err)
	}
	s := ni.buildScript()
	for _, want := range []string{
		`set acct_up4 { type ipv4_addr; flags dynamic; size 65535; counter; }`,
		`set acct_down4 { type ipv4_addr; flags dynamic; size 65535; counter; }`,
		`set acct_up6 { type ipv6_addr; flags dynamic; size 65535; counter; }`,
		`chain acct_ingress {`,
		`type filter hook prerouting priority -300;`,
		`ip saddr 10.66.0.0/24 update @acct_up4 { ip saddr }`,
		`chain acct_egress {`,
		`type filter hook postrouting priority -300;`,
		`ip daddr 10.66.0.0/24 update @acct_down4 { ip daddr }`,
		`ip6 daddr fd00:66::/64 update @acct_down6 { ip6 daddr }`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("accounting script missing %q\nscript:\n%s", want, s)
		}
	}
}

// TestParseNFTSetCounters validates the JSON parser against the two
// element shapes nft emits, ignoring counterless elements.
func TestParseNFTSetCounters(t *testing.T) {
	data := []byte(`{"nftables":[
		{"metainfo":{"version":"1.0.9"}},
		{"set":{"family":"inet","name":"acct_up4","table":"packethose","type":"ipv4_addr","flags":["dynamic"],"elem":[
			{"elem":{"val":"10.66.0.10","counter":{"packets":3,"bytes":4096}}},
			{"elem":{"val":"10.66.0.11","counter":{"packets":1,"bytes":512}}},
			"10.66.0.99"
		]}}
	]}`)
	got, err := parseNFTSetCounters(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 counted elements, got %d: %v", len(got), got)
	}
	if got[netip.MustParseAddr("10.66.0.10")] != 4096 {
		t.Errorf("10.66.0.10: got %d want 4096", got[netip.MustParseAddr("10.66.0.10")])
	}
	if got[netip.MustParseAddr("10.66.0.11")] != 512 {
		t.Errorf("10.66.0.11: got %d want 512", got[netip.MustParseAddr("10.66.0.11")])
	}
	if _, ok := got[netip.MustParseAddr("10.66.0.99")]; ok {
		t.Error("counterless element should be skipped")
	}
}
