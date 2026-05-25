package packethose

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFileAndApply(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	body := `
listen: 0.0.0.0:4500
lanes: 4
mptcp: false
cipher: aes-gcm
bbr: true
brutal:
  enabled: false
  rate_mbps: 0
pool:
  v4_subnet: 10.66.0.0/24
  server_ip4: 10.66.0.1
users:
  - name: alice
    psk_hex: "0102030405060708090a0b0c0d0e0f10"
    max_concurrent: 3
  - name: bob
    psk_hex: "1112131415161718191a1b1c1d1e1f20"
    max_concurrent: 2
    reserved: [10.66.0.5]
forward:
  isolation: true
  masquerade: true
  tproxy: false
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	fc, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if fc.Listen != "0.0.0.0:4500" {
		t.Fatalf("listen: %q", fc.Listen)
	}
	if !fc.WantBBR() {
		t.Fatalf("WantBBR should be true")
	}
	users, err := fc.ToUsers()
	if err != nil {
		t.Fatalf("ToUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("users len: %d", len(users))
	}
	if users[1].Name != "bob" || len(users[1].Reserved) != 1 {
		t.Fatalf("bob: %#v", users[1])
	}

	var cfg ServerConfig
	if err := fc.ApplyServer(&cfg); err != nil {
		t.Fatalf("ApplyServer: %v", err)
	}
	if cfg.Listen != "0.0.0.0:4500" {
		t.Fatalf("Listen after apply: %q", cfg.Listen)
	}
	if !cfg.Subnet.IsValid() {
		t.Fatalf("Subnet not set")
	}
	if len(cfg.Users) != 2 {
		t.Fatalf("Users not set: %d", len(cfg.Users))
	}
	if !cfg.NFT.Enabled || !cfg.NFT.Isolation || !cfg.NFT.Masquerade {
		t.Fatalf("NFT not populated: %#v", cfg.NFT)
	}
	if cfg.NFT.TPROXY {
		t.Fatalf("forward.tproxy was false but NFT.TPROXY is true")
	}
	if cfg.TPROXY.Enabled {
		t.Fatalf("forward.tproxy was false but TPROXY.Enabled is true")
	}
}

func TestApplyForwardTPROXYEnabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	body := `
listen: 0.0.0.0:4500
pool:
  v4_subnet: 10.66.0.0/24
  server_ip4: 10.66.0.1
users:
  - name: alice
    psk_hex: "0102030405060708090a0b0c0d0e0f10"
forward:
  isolation: true
  masquerade: true
  tproxy: true
  tproxy_listen_port: 13338
  tproxy_fwmark: 1
  tproxy_table: 13338
  tun_match: "phose-*"
tproxy:
  udp_idle_secs: 30
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	fc, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	var cfg ServerConfig
	if err := fc.ApplyServer(&cfg); err != nil {
		t.Fatalf("ApplyServer: %v", err)
	}
	if !cfg.NFT.Enabled || !cfg.NFT.TPROXY || !cfg.NFT.Isolation || !cfg.NFT.Masquerade {
		t.Fatalf("nft not fully populated: %#v", cfg.NFT)
	}
	if cfg.NFT.TPROXYPort != 13338 || cfg.NFT.TPROXYMark != 1 || cfg.NFT.RouteTable != 13338 {
		t.Fatalf("nft tproxy params: %#v", cfg.NFT)
	}
	if cfg.NFT.TUNMatch != "phose-*" {
		t.Fatalf("tun_match: %q", cfg.NFT.TUNMatch)
	}
	if !cfg.TPROXY.Enabled || cfg.TPROXY.ListenPort != 13338 {
		t.Fatalf("tproxy listener not enabled or wrong port: %#v", cfg.TPROXY)
	}
	if !cfg.TPROXY.EnforceIsolation {
		t.Fatalf("tproxy isolation default should follow forward.isolation")
	}
	if cfg.TPROXY.UDPIdleTimeout.Seconds() != 30 {
		t.Fatalf("udp idle: %v", cfg.TPROXY.UDPIdleTimeout)
	}
	if !cfg.TPROXY.PoolV4.IsValid() || cfg.TPROXY.PoolV4.String() != "10.66.0.0/24" {
		t.Fatalf("pool v4 not threaded into tproxy: %v", cfg.TPROXY.PoolV4)
	}
}
