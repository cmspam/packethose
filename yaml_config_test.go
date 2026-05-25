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
}
