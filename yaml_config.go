package packethose

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// FileConfig is the on-disk YAML schema. It is a superset of the CLI
// flags: a server can be configured exclusively from this file, or
// the file can be omitted entirely and the CLI flags drive
// everything. Fields left zero in the YAML keep their CLI-supplied
// or built-in default.
type FileConfig struct {
	Listen    string         `yaml:"listen"`
	Lanes     int            `yaml:"lanes"`
	MPTCP     bool           `yaml:"mptcp"`
	Cipher    string         `yaml:"cipher"`
	BBR       *bool          `yaml:"bbr"`
	VnetHdr   *bool          `yaml:"vnet_hdr"`
	AllowIP   string         `yaml:"allow_ip"`
	TUNPrefix string         `yaml:"tun_prefix"`
	ServerPSK string         `yaml:"server_psk"`
	Brutal    BrutalConfig   `yaml:"brutal"`
	Pool      PoolConfig     `yaml:"pool"`
	Users     []UserFile     `yaml:"users"`
	Forward   ForwardConfig  `yaml:"forward"`
	NFT       NFTFileConfig  `yaml:"nft"`
	TPROXY    TPROXYFileConf `yaml:"tproxy"`
}

// BrutalConfig configures the tcp-brutal congestion control wrapper.
type BrutalConfig struct {
	Enabled  bool `yaml:"enabled"`
	RateMbps int  `yaml:"rate_mbps"`
}

// PoolConfig describes the address pool for the multi-client server.
type PoolConfig struct {
	V4Subnet  string `yaml:"v4_subnet"`
	V6Subnet  string `yaml:"v6_subnet"`
	ServerIP4 string `yaml:"server_ip4"`
	ServerIP6 string `yaml:"server_ip6"`
}

// UserFile is the YAML form of a User entry.
type UserFile struct {
	Name          string   `yaml:"name"`
	PSKHex        string   `yaml:"psk_hex"`
	MaxConcurrent int      `yaml:"max_concurrent"`
	Reserved      []string `yaml:"reserved"`
}

// ForwardConfig holds the forwarding posture: isolation, masquerade,
// and TPROXY all default off so loading the YAML alone never installs
// nftables rules without an explicit opt-in.
type ForwardConfig struct {
	Isolation        bool   `yaml:"isolation"`
	Masquerade       bool   `yaml:"masquerade"`
	TPROXY           bool   `yaml:"tproxy"`
	TPROXYListenPort int    `yaml:"tproxy_listen_port"`
	TPROXYFwmark     uint32 `yaml:"tproxy_fwmark"`
	TPROXYTable      uint32 `yaml:"tproxy_table"`
	EgressInterface  string `yaml:"egress_interface"`
	TUNMatch         string `yaml:"tun_match"`
}

// NFTFileConfig overrides the default nft table name and gives the
// operator a way to disable auto-install entirely.
type NFTFileConfig struct {
	Enabled   *bool  `yaml:"enabled"`
	TableName string `yaml:"table_name"`
	Family    string `yaml:"family"`
}

// TPROXYFileConf groups the TPROXY listener tunables that live
// alongside the nft rules.
type TPROXYFileConf struct {
	Enabled      *bool  `yaml:"enabled"`
	ListenAddr   string `yaml:"listen_addr"`
	ListenPort   int    `yaml:"listen_port"`
	Family       string `yaml:"family"`
	UDPIdleSecs  int    `yaml:"udp_idle_secs"`
	EnforceIso   *bool  `yaml:"enforce_isolation"`
}

// LoadFile parses a YAML file. An empty path returns an empty
// FileConfig and no error, so the caller can treat "no file given"
// and "file with no overrides" the same way.
func LoadFile(path string) (FileConfig, error) {
	var fc FileConfig
	if path == "" {
		return fc, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return fc, fmt.Errorf("config %s: %w", path, err)
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&fc); err != nil {
		return fc, fmt.Errorf("config %s: %w", path, err)
	}
	return fc, nil
}

// ToUsers parses the YAML user list into runtime User values.
func (fc FileConfig) ToUsers() ([]User, error) {
	out := make([]User, 0, len(fc.Users))
	for i, u := range fc.Users {
		psk, err := ParsePSKHex(u.PSKHex)
		if err != nil {
			return nil, fmt.Errorf("user %d (%q): %w", i, u.Name, err)
		}
		if len(psk) == 0 {
			return nil, fmt.Errorf("user %d (%q): psk_hex is required", i, u.Name)
		}
		var reserved []netip.Addr
		for _, s := range u.Reserved {
			a, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("user %q reserved %q: %w", u.Name, s, err)
			}
			reserved = append(reserved, a)
		}
		out = append(out, User{
			Name:          u.Name,
			PSK:           psk,
			MaxConcurrent: u.MaxConcurrent,
			Reserved:      reserved,
		})
	}
	return out, nil
}

// ApplyServer overlays YAML values onto a ServerConfig. Non-zero CLI
// fields already present on the input are preserved when the YAML
// field is empty, so the precedence rule is "CLI overrides YAML when
// both are set". A small set of fields, notably Users, are taken
// straight from the YAML because they have no CLI form.
func (fc FileConfig) ApplyServer(cfg *ServerConfig) error {
	if cfg == nil {
		return errors.New("ApplyServer: nil ServerConfig")
	}
	if cfg.Listen == "" && fc.Listen != "" {
		cfg.Listen = fc.Listen
	}
	if cfg.Lanes == 0 && fc.Lanes != 0 {
		cfg.Lanes = fc.Lanes
	}
	if !cfg.MPTCP && fc.MPTCP {
		cfg.MPTCP = true
	}
	if cfg.AllowIP == "" && fc.AllowIP != "" {
		cfg.AllowIP = fc.AllowIP
	}
	if cfg.TUNPrefix == "" && fc.TUNPrefix != "" {
		cfg.TUNPrefix = fc.TUNPrefix
	}
	if fc.VnetHdr != nil {
		cfg.VnetHdr = *fc.VnetHdr
	}
	if len(cfg.PSK) == 0 && fc.ServerPSK != "" {
		psk, err := ParsePSKHex(fc.ServerPSK)
		if err != nil {
			return err
		}
		cfg.PSK = psk
	}
	if fc.Pool.V4Subnet != "" {
		p, err := netip.ParsePrefix(fc.Pool.V4Subnet)
		if err != nil {
			return fmt.Errorf("pool.v4_subnet: %w", err)
		}
		cfg.Subnet = p
	}
	if fc.Pool.ServerIP4 != "" {
		a, err := netip.ParseAddr(fc.Pool.ServerIP4)
		if err != nil || !a.Is4() {
			return fmt.Errorf("pool.server_ip4: must be an IPv4 address")
		}
		cfg.ServerIP = a
	}
	if fc.Pool.V6Subnet != "" {
		p, err := netip.ParsePrefix(fc.Pool.V6Subnet)
		if err != nil {
			return fmt.Errorf("pool.v6_subnet: %w", err)
		}
		cfg.Subnet6 = p
	}
	if fc.Pool.ServerIP6 != "" {
		a, err := netip.ParseAddr(fc.Pool.ServerIP6)
		if err != nil || !a.Is6() {
			return fmt.Errorf("pool.server_ip6: must be an IPv6 address")
		}
		cfg.ServerIP6 = a
	}
	users, err := fc.ToUsers()
	if err != nil {
		return err
	}
	if len(users) > 0 {
		cfg.Users = users
	}
	return nil
}

// CipherChoice returns the parsed Cipher from the YAML or
// CipherNone when the field is empty.
func (fc FileConfig) CipherChoice() (Cipher, error) {
	if fc.Cipher == "" {
		return CipherNone, nil
	}
	return ParseCipher(fc.Cipher)
}

// WantBBR returns whether BBR should be applied per socket. When the
// YAML omits the field, the function returns true (BBR is the
// default for the VPN-provider profile and is safely no-oped on
// kernels that lack it).
func (fc FileConfig) WantBBR() bool {
	if fc.BBR == nil {
		return true
	}
	return *fc.BBR
}
