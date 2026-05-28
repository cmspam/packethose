package packethose

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFileAndApply(t *testing.T) {
	serverPriv, _, _ := GenerateKeypair()
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	body := fmt.Sprintf(`
listen: 0.0.0.0:4500
lanes: 4
mptcp: false
cipher: aes-gcm
bbr: true
server_private_key: %q
brutal:
  enabled: false
  rate_mbps: 0
pool:
  v4_subnet: 10.66.0.0/24
  server_ip4: 10.66.0.1
users:
  - name: alice
    public_key: %q
    max_concurrent: 3
  - name: bob
    public_key: %q
    max_concurrent: 2
    reserved: [10.66.0.5]
forward:
  isolation: true
  masquerade: true
  tproxy: false
  metering: true
`, FormatKey(serverPriv), FormatKey(testPub(0xaa)), FormatKey(testPub(0xbb)))
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	fc, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if !fc.WantBBR() {
		t.Fatalf("WantBBR should be true")
	}
	users, err := fc.ToUsers()
	if err != nil {
		t.Fatalf("ToUsers: %v", err)
	}
	if len(users) != 2 || users[1].Name != "bob" || len(users[1].Reserved) != 1 {
		t.Fatalf("users: %#v", users)
	}

	var cfg ServerConfig
	if err := fc.ApplyServer(&cfg); err != nil {
		t.Fatalf("ApplyServer: %v", err)
	}
	if cfg.Listen != "0.0.0.0:4500" {
		t.Fatalf("Listen after apply: %q", cfg.Listen)
	}
	if len(cfg.StaticPrivateKey) != pubKeyLen {
		t.Fatalf("StaticPrivateKey not set: %d", len(cfg.StaticPrivateKey))
	}
	if cfg.Cipher != CipherAESGCM {
		t.Fatalf("Cipher not applied: %v", cfg.Cipher)
	}
	if !cfg.Subnet.IsValid() || len(cfg.Users) != 2 {
		t.Fatalf("pool/users not set")
	}
	if !cfg.NFT.Enabled || !cfg.NFT.Isolation || !cfg.NFT.Masquerade || !cfg.NFT.Accounting {
		t.Fatalf("NFT not populated: %#v", cfg.NFT)
	}
	if !cfg.NFT.PoolV4.IsValid() {
		t.Fatalf("accounting needs PoolV4 threaded in")
	}
	if cfg.NFT.TPROXY || cfg.TPROXY.Enabled {
		t.Fatalf("forward.tproxy was false but TPROXY is on")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestApplyForwardTPROXYEnabled(t *testing.T) {
	serverPriv, _, _ := GenerateKeypair()
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	body := fmt.Sprintf(`
listen: 0.0.0.0:4500
server_private_key: %q
pool:
  v4_subnet: 10.66.0.0/24
  server_ip4: 10.66.0.1
users:
  - name: alice
    public_key: %q
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
`, FormatKey(serverPriv), FormatKey(testPub(0xaa)))
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
