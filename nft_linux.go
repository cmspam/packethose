//go:build linux

package packethose

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

// NFTConfig describes the auto-installed nftables ruleset packethose
// owns at runtime. The whole block is opt-in: an Installer with
// Enabled=false (the default) is a no-op.
//
// Packethose only ever creates and tears down a single dedicated
// table. It never edits another table. The default table family is
// "inet", the default name is "packethose".
type NFTConfig struct {
	Enabled bool

	// Family is the nft family of the table, "inet" by default.
	Family string

	// TableName is the table name. Default "packethose".
	TableName string

	// TUNMatch is the interface-name match expression applied to
	// per-client TUN devices, "phose-*" by default. The asterisk is
	// nft's wildcard glob.
	TUNMatch string

	// Isolation enables the FORWARD chain rule that drops
	// inter-client traffic. With this on, packethose's TPROXY
	// listener must also check the dial-side destination, since
	// TPROXY traffic bypasses FORWARD.
	Isolation bool

	// Masquerade enables postrouting MASQ on egress out of the TUN
	// family. EgressInterface, when non-empty, restricts the MASQ
	// rule to that interface; empty means "any non-phose-* output".
	Masquerade      bool
	EgressInterface string

	// TPROXY enables the prerouting rule that catches TCP/UDP on
	// the matching interface and redirects to the local listener.
	// The fwmark is set on the matched packets so the local routing
	// rule can lift them into the TPROXY table.
	TPROXY     bool
	TPROXYPort int
	TPROXYMark uint32

	// IPRule + IPRoute auto-install. RouteTable is the routing-
	// table id used in the lookup; the rule and route are installed
	// together with the nft table and removed together when Stop()
	// runs.
	RouteTable uint32
	IPv4       bool
	IPv6       bool

	// ServerIP4 and ServerIP6 are the server's own tunnel-side
	// addresses (e.g. 10.66.0.1 and fd00:66::1). When TPROXY is
	// enabled, packets destined to these addresses are accepted in
	// the prerouting chain before the tproxy redirect, so a client
	// can reach services on the server's tunnel IP (iperf3, sshd
	// bound to it) via the kernel's normal local delivery path
	// rather than looping through the tproxy listener.
	ServerIP4 netip.Addr
	ServerIP6 netip.Addr

	// Accounting installs per-client byte counters keyed on the pool
	// address. Counting happens in the kernel at prerouting and
	// postrouting, so it is free on the data path and covers both
	// forwarded and TPROXY-terminated traffic. Requires PoolV4 and/or
	// PoolV6 to be set. Read the counters with Stats() or directly via
	// `nft -j list set <family> <table> acct_up4`.
	Accounting bool
	PoolV4     netip.Prefix
	PoolV6     netip.Prefix
}

// nftBin is the nftables(8) binary path. Overridable for tests.
var nftBin = "nft"

// ipBin is iproute2's ip(8) binary path.
var ipBin = "ip"

// NFTInstaller owns the lifecycle of the packethose nft table and its
// companion ip rule / ip route. Methods are safe to call multiple
// times: Install is idempotent (existing table is flushed and
// replaced atomically), Remove tolerates an already-gone table.
type NFTInstaller struct {
	cfg    NFTConfig
	logger *log.Logger
}

// NewNFTInstaller validates cfg and returns an installer. Defaults
// are applied to Family, TableName, and TUNMatch.
func NewNFTInstaller(cfg NFTConfig, logger *log.Logger) (*NFTInstaller, error) {
	if logger == nil {
		logger = log.Default()
	}
	if !cfg.Enabled {
		return &NFTInstaller{cfg: cfg, logger: logger}, nil
	}
	if cfg.Family == "" {
		cfg.Family = "inet"
	}
	if cfg.TableName == "" {
		cfg.TableName = "packethose"
	}
	if cfg.TUNMatch == "" {
		cfg.TUNMatch = "phose-*"
	}
	if cfg.TPROXY {
		if cfg.TPROXYPort == 0 {
			cfg.TPROXYPort = 13338
		}
		if cfg.TPROXYMark == 0 {
			cfg.TPROXYMark = 0x1
		}
		if cfg.RouteTable == 0 {
			cfg.RouteTable = uint32(cfg.TPROXYPort)
		}
		if !cfg.IPv4 && !cfg.IPv6 {
			cfg.IPv4 = true
			cfg.IPv6 = true
		}
	}
	if _, err := exec.LookPath(nftBin); err != nil {
		return nil, fmt.Errorf("nft binary not found: %w", err)
	}
	return &NFTInstaller{cfg: cfg, logger: logger}, nil
}

// Enabled reports whether the installer would actually install
// anything. Callers can short-circuit on this to skip diagnostic
// logging entirely.
func (n *NFTInstaller) Enabled() bool { return n.cfg.Enabled }

// Config returns a copy of the resolved configuration so callers can
// reuse Family/TableName/etc when wiring up companion paths such as
// the TPROXY listener address or fwmark.
func (n *NFTInstaller) Config() NFTConfig { return n.cfg }

// Install applies the configured ruleset. If a table with the same
// name already exists, it is replaced atomically: nft's add+flush
// dance inside a single transaction means concurrent traffic sees
// either the old rules or the new rules, never an empty table.
func (n *NFTInstaller) Install() error {
	if !n.cfg.Enabled {
		return nil
	}
	script := n.buildScript()
	if err := runNFT(script); err != nil {
		return fmt.Errorf("nft install: %w", err)
	}
	n.logger.Printf("nft: installed table %s %s", n.cfg.Family, n.cfg.TableName)
	if n.cfg.TPROXY {
		if err := n.installIPRouting(); err != nil {
			// Roll the nft table back; an IP rule failure means the
			// TPROXY redirect would mark packets that never get
			// lifted into the right routing table.
			_ = runNFT(n.removeScript())
			return fmt.Errorf("install ip rule/route: %w", err)
		}
		n.logger.Printf("nft: installed ip rule fwmark %#x lookup %d", n.cfg.TPROXYMark, n.cfg.RouteTable)
	}
	return nil
}

// Remove tears down the packethose table and any companion ip rule /
// ip route. It is idempotent and safe to call multiple times.
func (n *NFTInstaller) Remove() error {
	if !n.cfg.Enabled {
		return nil
	}
	var firstErr error
	if n.cfg.TPROXY {
		if err := n.removeIPRouting(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := runNFT(n.removeScript()); err != nil && firstErr == nil {
		firstErr = err
	} else {
		n.logger.Printf("nft: removed table %s %s", n.cfg.Family, n.cfg.TableName)
	}
	return firstErr
}

// Reconcile is the boot-time idempotent reload. A previous run that
// crashed may have left a stale table behind; Reconcile removes any
// existing table with the same name and reapplies the current
// ruleset.
func (n *NFTInstaller) Reconcile() error {
	if !n.cfg.Enabled {
		return nil
	}
	// Remove always-tolerates-missing; runNFT swallows the "no such
	// file" diagnostic.
	_ = runNFT(n.removeScript())
	_ = n.removeIPRouting()
	return n.Install()
}

// buildScript renders the nft ruleset as a single transaction. The
// `add table ... { ... }` outer block flushes the table to empty if
// it already exists, then installs the chains and rules in one
// commit.
func (n *NFTInstaller) buildScript() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "table %s %s {\n", n.cfg.Family, n.cfg.TableName)

	if n.cfg.TPROXY {
		fmt.Fprintf(&b, "  chain prerouting {\n")
		fmt.Fprintf(&b, "    type filter hook prerouting priority mangle; policy accept;\n")
		// Traffic destined to the server's own tunnel IPs is accepted
		// before the tproxy redirect so clients can reach services
		// bound to those addresses (iperf3 -s -B 10.66.0.1,
		// administrative sshd on the tunnel-IP, etc.) without
		// looping through the tproxy listener.
		if n.cfg.IPv4 && n.cfg.ServerIP4.IsValid() {
			fmt.Fprintf(&b, "    iifname %q ip daddr %s accept\n", n.cfg.TUNMatch, n.cfg.ServerIP4.String())
		}
		if n.cfg.IPv6 && n.cfg.ServerIP6.IsValid() {
			fmt.Fprintf(&b, "    iifname %q ip6 daddr %s accept\n", n.cfg.TUNMatch, n.cfg.ServerIP6.String())
		}
		if n.cfg.IPv4 {
			fmt.Fprintf(&b, "    iifname %q meta l4proto { tcp, udp } tproxy ip to :%d meta mark set %#x accept\n",
				n.cfg.TUNMatch, n.cfg.TPROXYPort, n.cfg.TPROXYMark)
		}
		if n.cfg.IPv6 {
			fmt.Fprintf(&b, "    iifname %q meta l4proto { tcp, udp } tproxy ip6 to :%d meta mark set %#x accept\n",
				n.cfg.TUNMatch, n.cfg.TPROXYPort, n.cfg.TPROXYMark)
		}
		fmt.Fprintf(&b, "  }\n")
	}

	if n.cfg.Isolation {
		fmt.Fprintf(&b, "  chain forward {\n")
		fmt.Fprintf(&b, "    type filter hook forward priority 0; policy accept;\n")
		fmt.Fprintf(&b, "    iifname %q oifname %q drop\n", n.cfg.TUNMatch, n.cfg.TUNMatch)
		fmt.Fprintf(&b, "  }\n")
	}

	if n.cfg.Masquerade {
		fmt.Fprintf(&b, "  chain postrouting {\n")
		fmt.Fprintf(&b, "    type nat hook postrouting priority srcnat; policy accept;\n")
		if n.cfg.EgressInterface != "" {
			fmt.Fprintf(&b, "    iifname %q oifname %q masquerade\n", n.cfg.TUNMatch, n.cfg.EgressInterface)
		} else {
			fmt.Fprintf(&b, "    iifname %q oifname != %q masquerade\n", n.cfg.TUNMatch, n.cfg.TUNMatch)
		}
		fmt.Fprintf(&b, "  }\n")
	}

	if n.cfg.Accounting {
		acctV4 := n.cfg.IPv4 && n.cfg.PoolV4.IsValid()
		acctV6 := n.cfg.IPv6 && n.cfg.PoolV6.IsValid()
		// Dynamic sets auto-create one counter per client address on its
		// first packet; `update` increments without terminating the
		// chain. Names are stable so Stats() and external pollers can
		// find them.
		if acctV4 {
			fmt.Fprintf(&b, "  set acct_up4 { type ipv4_addr; flags dynamic; size 65535; counter; }\n")
			fmt.Fprintf(&b, "  set acct_down4 { type ipv4_addr; flags dynamic; size 65535; counter; }\n")
		}
		if acctV6 {
			fmt.Fprintf(&b, "  set acct_up6 { type ipv6_addr; flags dynamic; size 65535; counter; }\n")
			fmt.Fprintf(&b, "  set acct_down6 { type ipv6_addr; flags dynamic; size 65535; counter; }\n")
		}
		// Ingress (client -> internet): count by source, before tproxy
		// or forward see the packet. Priority is the lowest so it runs
		// first and observes every byte.
		fmt.Fprintf(&b, "  chain acct_ingress {\n")
		fmt.Fprintf(&b, "    type filter hook prerouting priority -300; policy accept;\n")
		if acctV4 {
			fmt.Fprintf(&b, "    ip saddr %s update @acct_up4 { ip saddr }\n", n.cfg.PoolV4)
		}
		if acctV6 {
			fmt.Fprintf(&b, "    ip6 saddr %s update @acct_up6 { ip6 saddr }\n", n.cfg.PoolV6)
		}
		fmt.Fprintf(&b, "  }\n")
		// Egress (internet -> client): count by destination at
		// postrouting, after any return-path NAT has been undone.
		fmt.Fprintf(&b, "  chain acct_egress {\n")
		fmt.Fprintf(&b, "    type filter hook postrouting priority -300; policy accept;\n")
		if acctV4 {
			fmt.Fprintf(&b, "    ip daddr %s update @acct_down4 { ip daddr }\n", n.cfg.PoolV4)
		}
		if acctV6 {
			fmt.Fprintf(&b, "    ip6 daddr %s update @acct_down6 { ip6 daddr }\n", n.cfg.PoolV6)
		}
		fmt.Fprintf(&b, "  }\n")
	}

	fmt.Fprintf(&b, "}\n")
	return b.String()
}

func (n *NFTInstaller) removeScript() string {
	return fmt.Sprintf("delete table %s %s\n", n.cfg.Family, n.cfg.TableName)
}

func (n *NFTInstaller) installIPRouting() error {
	mark := fmt.Sprintf("%#x", n.cfg.TPROXYMark)
	table := strconv.FormatUint(uint64(n.cfg.RouteTable), 10)
	if n.cfg.IPv4 {
		if err := runIP(false, "rule", "add", "fwmark", mark, "lookup", table); err != nil {
			return err
		}
		if err := runIP(false, "route", "add", "local", "default", "dev", "lo", "table", table); err != nil {
			return err
		}
	}
	if n.cfg.IPv6 {
		if err := runIP(true, "rule", "add", "fwmark", mark, "lookup", table); err != nil {
			return err
		}
		if err := runIP(true, "route", "add", "local", "default", "dev", "lo", "table", table); err != nil {
			return err
		}
	}
	return nil
}

func (n *NFTInstaller) removeIPRouting() error {
	mark := fmt.Sprintf("%#x", n.cfg.TPROXYMark)
	table := strconv.FormatUint(uint64(n.cfg.RouteTable), 10)
	var firstErr error
	swallow := func(err error) {
		if err != nil && firstErr == nil && !isIPNotPresent(err) {
			firstErr = err
		}
	}
	if n.cfg.IPv4 {
		swallow(runIP(false, "rule", "del", "fwmark", mark, "lookup", table))
		swallow(runIP(false, "route", "del", "local", "default", "dev", "lo", "table", table))
	}
	if n.cfg.IPv6 {
		swallow(runIP(true, "rule", "del", "fwmark", mark, "lookup", table))
		swallow(runIP(true, "route", "del", "local", "default", "dev", "lo", "table", table))
	}
	return firstErr
}

func runNFT(script string) error {
	cmd := exec.Command(nftBin, "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		// Tolerate "no such file or directory" when removing a table
		// that is already gone. The caller is responsible for
		// deciding whether to ignore.
		if strings.Contains(msg, "No such file") || strings.Contains(msg, "does not exist") {
			return errNFTNotPresent
		}
		if msg == "" {
			return err
		}
		return fmt.Errorf("%s: %w", msg, err)
	}
	return nil
}

// errNFTNotPresent is returned by runNFT when the operation referenced
// a table or chain that does not exist. Treated as a benign no-op by
// idempotent code paths.
var errNFTNotPresent = errors.New("nft: object not present")

func runIP(v6 bool, args ...string) error {
	full := args
	if v6 {
		full = append([]string{"-6"}, args...)
	}
	cmd := exec.Command(ipBin, full...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			return err
		}
		return fmt.Errorf("%s: %w", msg, err)
	}
	return nil
}

func isIPNotPresent(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "No such") || strings.Contains(s, "RTNETLINK answers: No such file") ||
		strings.Contains(s, "Cannot find")
}
