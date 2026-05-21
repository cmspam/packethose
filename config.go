package packethose

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
)

// Cipher selects the AEAD used for per-frame payload protection.
type Cipher byte

const (
	// CipherNone disables encryption. Handshake (if PSK is set) still
	// authenticates the connection.
	CipherNone Cipher = 0
	// CipherAESGCM is AES-128 in GCM mode. Hardware-accelerated on every
	// modern x86/ARM CPU; preferred default.
	CipherAESGCM Cipher = 1
	// CipherChaCha is ChaCha20-Poly1305. Fallback for hardware without AES
	// instructions.
	CipherChaCha Cipher = 2
)

func (c Cipher) String() string {
	switch c {
	case CipherNone:
		return "none"
	case CipherAESGCM:
		return "aes-gcm"
	case CipherChaCha:
		return "chacha20"
	}
	return fmt.Sprintf("unknown(%d)", byte(c))
}

// ParseCipher parses a cipher name. Accepts "none", "aes-gcm" (or "aes"),
// "chacha20" (or "chacha20-poly1305"), or the empty string (same as "none").
func ParseCipher(s string) (Cipher, error) {
	switch s {
	case "", "none":
		return CipherNone, nil
	case "aes-gcm", "aes":
		return CipherAESGCM, nil
	case "chacha20", "chacha20-poly1305":
		return CipherChaCha, nil
	}
	return CipherNone, fmt.Errorf("unknown cipher %q (want none|aes-gcm|chacha20)", s)
}

// ContextDialer is the minimal dialer interface packethose needs for outer
// lane TCPs. Both *net.Dialer and mihomo's proxydialer.NewDialer satisfy it.
type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// ClientConfig configures a packethose client.
type ClientConfig struct {
	// Peer is the server's "addr:port".
	Peer string
	// Lanes is the number of parallel outer TCP connections. Inner flows
	// hash to one lane each.
	Lanes int
	// Queues supplies one PacketIO per lane. Use OpenKernelTUN to get a
	// kernel-TUN-backed set, or supply your own.
	Queues []PacketIO

	// PSK enables the HMAC-based handshake. Required when Cipher != none.
	PSK []byte
	// Cipher selects the AEAD for payload protection.
	Cipher Cipher
	// MPTCP enables Multipath TCP on the outer sockets.
	MPTCP bool

	// Dialer is used for outer-lane TCP dials. nil = a default net.Dialer
	// with a 10s timeout. Set this to plug in mihomo's proxydialer or any
	// other transport.
	Dialer ContextDialer

	// TuneSocket, if non-nil, is invoked on every fresh outer TCP after
	// the built-in tuning (NoDelay, keepalive, SO_*BUF). Use this hook to
	// install custom socket options like tcp-brutal (see SetBrutalRate).
	TuneSocket func(net.Conn)

	// ClientID is the 16-byte identifier sent on every lane's handshake.
	// When the server is in multi-client mode it groups lanes by this ID
	// and assigns addresses per ID. Zero = NewClient generates a random
	// one.
	ClientID [clientIDLen]byte

	// RequestIP and RequestIP6, if set, are the IPv4 and/or IPv6 addresses
	// the client would prefer to be assigned. The server may honor them
	// (sticky across reconnects) or assign different ones. Either can be
	// the zero Addr to skip a family.
	RequestIP  netip.Addr
	RequestIP6 netip.Addr

	// OnAssigned is invoked once per Client lifetime when the server
	// returns any assignment (v4, v6, or both). Use it to configure your
	// TUN device or netstack with the assigned addresses after the first
	// lane comes up.
	OnAssigned func(Assignment)

	// Logger receives lane lifecycle messages. nil = log.Default().
	Logger *log.Logger
}

// ServerConfig configures a packethose server.
type ServerConfig struct {
	// Listen is the bind address, e.g. "0.0.0.0:4500" or "[::]:4500".
	Listen string
	// Lanes is the number of lanes to service. Queues must have this length.
	Lanes  int
	Queues []PacketIO

	// PSK enables the handshake. Required when clients connect with
	// encryption set.
	PSK []byte
	// AllowIP, if non-empty, restricts accepted connections to this source
	// IP. The check happens before the handshake.
	AllowIP string
	// MPTCP enables Multipath TCP on the listener.
	MPTCP bool

	// ListenConfig is an optional custom listener config. nil = a default
	// one. If MPTCP is true and ListenConfig is nil, a default
	// MPTCP-enabled ListenConfig is constructed.
	ListenConfig *net.ListenConfig

	// TuneSocket, if non-nil, is invoked on every freshly accepted outer
	// TCP after the built-in tuning (NoDelay, keepalive, SO_*BUF). Use to
	// install custom socket options (e.g. tcp-brutal via SetBrutalRate).
	TuneSocket func(net.Conn)

	// Logger receives lifecycle messages.
	Logger *log.Logger

	// Subnet (IPv4) and/or Subnet6 (IPv6), when set, switch the server
	// into multi-client mode: each connecting client is allocated a /32
	// from Subnet and/or a /128 (hash-derived) from Subnet6, and gets its
	// own kernel TUN. Either or both may be set; if neither is set, the
	// server runs the legacy single-client Queues-backed path.
	Subnet  netip.Prefix
	Subnet6 netip.Prefix
	// ServerIP and ServerIP6 are the host's tunnel-side addresses (e.g.
	// 10.66.0.1 and fd00:66::1). Required for their respective families
	// when Subnet/Subnet6 is set.
	ServerIP  netip.Addr
	ServerIP6 netip.Addr
	// TUNPrefix is the device-name prefix for per-client TUNs in
	// multi-client mode (default "phose"). Each client gets
	// <prefix>-<short-id>.
	TUNPrefix string
	// VnetHdr enables IFF_VNET_HDR on the per-client TUN devices in
	// multi-client mode.
	VnetHdr bool
}

// Validate returns nil if the config is internally consistent.
func (c ClientConfig) Validate() error {
	if c.Peer == "" {
		return errors.New("packethose client: Peer is required")
	}
	if c.Lanes < 1 {
		return errors.New("packethose client: Lanes must be >= 1")
	}
	if len(c.Queues) != c.Lanes {
		return fmt.Errorf("packethose client: Queues has %d entries, expected Lanes=%d", len(c.Queues), c.Lanes)
	}
	if c.Cipher != CipherNone && len(c.PSK) == 0 {
		return errors.New("packethose client: PSK required when Cipher is set")
	}
	return nil
}

// Validate returns nil if the config is internally consistent.
func (c ServerConfig) Validate() error {
	if c.Listen == "" {
		return errors.New("packethose server: Listen is required")
	}
	if c.Subnet.IsValid() || c.Subnet6.IsValid() {
		if len(c.PSK) == 0 {
			return errors.New("packethose server: multi-client mode requires PSK")
		}
		if c.Subnet.IsValid() {
			if !c.ServerIP.IsValid() || !c.ServerIP.Is4() {
				return errors.New("packethose server: Subnet requires an IPv4 ServerIP")
			}
			if !c.Subnet.Contains(c.ServerIP) {
				return fmt.Errorf("packethose server: ServerIP %s not in Subnet %s", c.ServerIP, c.Subnet)
			}
		}
		if c.Subnet6.IsValid() {
			if !c.ServerIP6.IsValid() || !c.ServerIP6.Is6() {
				return errors.New("packethose server: Subnet6 requires an IPv6 ServerIP6")
			}
			if !c.Subnet6.Contains(c.ServerIP6) {
				return fmt.Errorf("packethose server: ServerIP6 %s not in Subnet6 %s", c.ServerIP6, c.Subnet6)
			}
		}
		return nil
	}
	if c.Lanes < 1 {
		return errors.New("packethose server: Lanes must be >= 1")
	}
	if len(c.Queues) != c.Lanes {
		return fmt.Errorf("packethose server: Queues has %d entries, expected Lanes=%d", len(c.Queues), c.Lanes)
	}
	return nil
}
