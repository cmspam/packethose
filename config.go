package packethose

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
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
	if c.Lanes < 1 {
		return errors.New("packethose server: Lanes must be >= 1")
	}
	if len(c.Queues) != c.Lanes {
		return fmt.Errorf("packethose server: Queues has %d entries, expected Lanes=%d", len(c.Queues), c.Lanes)
	}
	return nil
}
