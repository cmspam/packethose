package packethose

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"
)

// Cipher selects the AEAD used for per-frame payload protection.
type Cipher byte

const (
	// CipherNone is the zero value. In keyed mode the suite defaults to
	// AES-128-GCM; CipherNone as a transport selection means open mode only.
	CipherNone Cipher = 0
	// CipherAESGCM is AES-128-GCM. Hardware-accelerated on every modern
	// x86/ARM CPU and the fastest option; the default.
	CipherAESGCM Cipher = 1
	// CipherChaCha is ChaCha20-Poly1305. Fallback for hardware without AES
	// instructions.
	CipherChaCha Cipher = 2
	// CipherAES256GCM is AES-256-GCM, for deployments that require a
	// 256-bit data key. Slower than AES-128 (more rounds) but still
	// hardware-accelerated.
	CipherAES256GCM Cipher = 3
)

func (c Cipher) String() string {
	switch c {
	case CipherNone:
		return "none"
	case CipherAESGCM:
		return "aes-128-gcm"
	case CipherChaCha:
		return "chacha20"
	case CipherAES256GCM:
		return "aes-256-gcm"
	}
	return fmt.Sprintf("unknown(%d)", byte(c))
}

// ParseCipher parses a cipher name. "aes-gcm"/"aes"/"aes-128-gcm" select
// AES-128-GCM (the default); "aes-256-gcm" selects AES-256-GCM;
// "chacha20"/"chacha20-poly1305" select ChaCha20-Poly1305; "" / "none"
// is open mode.
func ParseCipher(s string) (Cipher, error) {
	switch s {
	case "", "none":
		return CipherNone, nil
	case "aes-gcm", "aes", "aes-128-gcm", "aes-128":
		return CipherAESGCM, nil
	case "aes-256-gcm", "aes-256":
		return CipherAES256GCM, nil
	case "chacha20", "chacha20-poly1305":
		return CipherChaCha, nil
	}
	return CipherNone, fmt.Errorf("unknown cipher %q (want none|aes-128-gcm|aes-256-gcm|chacha20)", s)
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

	// StaticPrivateKey is this client's 32-byte X25519 static private
	// key (its identity). Empty selects open mode: no handshake, no
	// encryption.
	StaticPrivateKey []byte
	// PeerPublicKey is the server's 32-byte X25519 static public key,
	// known in advance (the Noise IK pre-message) and also the source of
	// the obfuscation-envelope key. Required when StaticPrivateKey is set.
	PeerPublicKey []byte
	// Cipher selects the AEAD suite for the Noise handshake and
	// transport. Must match the server's configured suite.
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

	// StaticPrivateKey is the server's 32-byte X25519 static private key
	// (its identity). Its public half is published to clients and also
	// keys the obfuscation envelope. Empty selects open mode: no
	// handshake, no encryption.
	StaticPrivateKey []byte
	// PeerPublicKey, when set, is the single authorized client static
	// public key (single-peer mode). Ignored when Users is populated.
	PeerPublicKey []byte
	// Users, when non-empty, switches the server into multi-client
	// identity mode: each connecting client is authorized by its static
	// public key against this list.
	Users []User
	// Cipher selects the AEAD suite for the Noise handshake and
	// transport. Clients must be configured with the same suite.
	Cipher Cipher
	// AllowIP, if non-empty, restricts accepted connections to this source
	// IP. The check happens before the handshake.
	AllowIP string
	// MetricsAddr, when non-empty, is the addr:port for a read-only HTTP
	// server exposing Prometheus /metrics and /healthz. Off by default.
	MetricsAddr string
	// RateLimit tunes the accept-path abuse controls (per-source-IP
	// connection rate and a server-wide in-flight-handshake cap). The
	// zero value is a sensible default posture.
	RateLimit RateLimitConfig
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
	// TUNName is the name of the single shared TUN device the
	// multi-client server opens for all sessions (default "phose0").
	// One device, multi-queue, with the pool /N and /M assigned
	// directly to it; per-client routing is by IP in userspace.
	TUNName string
	// VnetHdr enables IFF_VNET_HDR on the shared TUN device.
	VnetHdr bool
	// SharedTUNQueues controls how many multi-queue file descriptors
	// the shared TUN is opened with. Defaults to runtime.NumCPU(). Each
	// queue gets its own reader goroutine that dispatches by inner dst
	// IP to per-session channels.
	SharedTUNQueues int

	// NFT, when Enabled is true, installs a dedicated nftables table
	// at startup (and removes it at shutdown) with forwarding,
	// isolation, masquerade, and TPROXY rules per the config. See
	// NFTInstaller.
	NFT NFTConfig

	// TPROXY, when Enabled is true, runs a TPROXY listener that
	// terminates client TCP and UDP flows in kernel space and dials
	// the original destination directly. Pair with NFT.TPROXY = true
	// so the kernel actually redirects matching traffic to this
	// listener.
	TPROXY TPROXYConfig
}

// TPROXYConfig configures the packethose TPROXY termination listener.
// Pair with an NFT installer that redirects matching traffic to
// ListenPort, and an IP rule that lifts marked packets into the same
// routing table as the listener binds inside.
type TPROXYConfig struct {
	Enabled bool

	// ListenAddr is the loopback bind address. Empty defaults to
	// "127.0.0.1" (v4) plus "[::1]" (v6); the listener opens one
	// dual-stack socket on ListenPort.
	ListenAddr string

	// ListenPort is the TPROXY listener port. Default 13338.
	ListenPort int

	// UDPIdleTimeout is the per-flow idle timeout for UDP. Default
	// 60s.
	UDPIdleTimeout time.Duration

	// EnforceIsolation rejects dials whose destination falls inside
	// the configured pool subnets. Set true when isolation is on; the
	// nftables forward chain does not see TPROXY'd traffic.
	EnforceIsolation bool

	// PoolV4 / PoolV6 are the pool subnets used by the isolation
	// check. The Server populates them from cfg.Subnet / cfg.Subnet6
	// at startup so the listener does not need a back-reference.
	PoolV4 netip.Prefix
	PoolV6 netip.Prefix

	// ServerIP4 / ServerIP6 are the server's own tunnel-side
	// addresses. The isolation check exempts these so clients can
	// always reach services bound to the server's tunnel IP even
	// when the IP falls inside the pool subnet.
	ServerIP4 netip.Addr
	ServerIP6 netip.Addr
}

// keyed reports whether the client runs an authenticated, encrypted
// session (a static keypair is configured) versus open plaintext mode.
func (c ClientConfig) keyed() bool { return len(c.StaticPrivateKey) > 0 }

// keyed reports whether the server runs authenticated sessions.
func (c ServerConfig) keyed() bool { return len(c.StaticPrivateKey) > 0 }

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
	if len(c.StaticPrivateKey) > 0 {
		if len(c.StaticPrivateKey) != pubKeyLen {
			return fmt.Errorf("packethose client: StaticPrivateKey must be %d bytes", pubKeyLen)
		}
		if len(c.PeerPublicKey) != pubKeyLen {
			return errors.New("packethose client: PeerPublicKey (server public key) required with StaticPrivateKey")
		}
	} else if len(c.PeerPublicKey) > 0 {
		return errors.New("packethose client: PeerPublicKey set without StaticPrivateKey")
	}
	return nil
}

// Validate returns nil if the config is internally consistent.
func (c ServerConfig) Validate() error {
	if c.Listen == "" {
		return errors.New("packethose server: Listen is required")
	}
	if len(c.StaticPrivateKey) > 0 && len(c.StaticPrivateKey) != pubKeyLen {
		return fmt.Errorf("packethose server: StaticPrivateKey must be %d bytes", pubKeyLen)
	}
	hasAuth := len(c.PeerPublicKey) > 0 || len(c.Users) > 0
	if c.Subnet.IsValid() || c.Subnet6.IsValid() {
		if !c.keyed() || !hasAuth {
			return errors.New("packethose server: multi-client mode requires a server static key and at least one authorized client key (peer or users)")
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
