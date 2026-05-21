package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/cmspam/packethose"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	mode := os.Args[1]
	args := os.Args[2:]

	switch mode {
	case "client":
		runClient(args)
	case "server":
		runServer(args)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `packethose: userspace TUN + multi-lane TCP/MPTCP tunnel

  packethose server --listen ADDR:PORT --tun NAME --lanes N [flags]
  packethose client --peer ADDR:PORT  --tun NAME --lanes N [flags]

Common flags:
  --psk HEX            pre-shared key (hex). empty = no handshake
  --encrypt CIPHER     none | aes-gcm | chacha20 (requires --psk)
  --vnet_hdr           enable IFF_VNET_HDR for GRO/GSO batching (Linux)
  --mptcp              enable MPTCP on outer sockets

Server-only:
  --allow IP           accept only from this source IP

Bring the TUN interface up + assign addresses externally:
  ip link set ph0 up
  ip addr add 10.55.0.1/24 dev ph0
`)
}

type commonFlags struct {
	tun         string
	lanes       int
	pskHex      string
	mptcp       bool
	vnetHdr     bool
	encrypt     string
	brutalMbps  int
}

func bindCommon(fs *flag.FlagSet, c *commonFlags) {
	fs.StringVar(&c.tun, "tun", "ph0", "TUN device name (multi-queue)")
	fs.IntVar(&c.lanes, "lanes", 4, "number of parallel TCP lanes")
	fs.StringVar(&c.pskHex, "psk", "", "pre-shared key (hex). empty = no handshake")
	fs.BoolVar(&c.mptcp, "mptcp", false, "enable MPTCP on outer sockets")
	// vnet_hdr is the fast path on Linux (GRO/GSO super-packets). On by
	// default; opt out with --vnet_hdr=false for very old kernels lacking
	// IFF_VNET_HDR support.
	c.vnetHdr = true
	fs.BoolVar(&c.vnetHdr, "vnet_hdr", true, "open TUN with IFF_VNET_HDR for GRO/GSO batching (default on, Linux only)")
	fs.StringVar(&c.encrypt, "encrypt", "none", "AEAD cipher: none|aes-gcm|chacha20 (requires --psk)")
	fs.IntVar(&c.brutalMbps, "brutal_mbps", 0, "if non-zero, configure tcp-brutal CC on lanes at this Mbps")
}

func brutalTuner(mbps int) func(net.Conn) {
	if mbps <= 0 {
		return nil
	}
	rate := uint64(mbps) * 1_000_000 / 8
	return packethose.BrutalTuner(rate, 0, log.Printf)
}

func parsePSK(s string) []byte {
	if s == "" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		log.Fatalf("--psk must be hex: %v", err)
	}
	if len(b) < 16 {
		log.Fatalf("--psk must be at least 16 bytes")
	}
	return b
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-ch
		cancel()
	}()
	return ctx, cancel
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	var (
		cf        commonFlags
		listen    string
		allow     string
		subnet    string
		serverIP  string
		subnet6   string
		serverIP6 string
		tunPrefix string
	)
	bindCommon(fs, &cf)
	fs.StringVar(&listen, "listen", "0.0.0.0:4500", "TCP listen address")
	fs.StringVar(&allow, "allow", "", "if set, only accept from this source IP")
	fs.StringVar(&subnet, "subnet", "", "multi-client IPv4 subnet (CIDR, e.g. 10.66.0.0/24); requires --psk")
	fs.StringVar(&serverIP, "server-ip", "", "multi-client tunnel-side IPv4 server IP (required with --subnet)")
	fs.StringVar(&subnet6, "subnet6", "", "multi-client IPv6 subnet (CIDR, e.g. fd00:66::/64); requires --psk")
	fs.StringVar(&serverIP6, "server-ip6", "", "multi-client tunnel-side IPv6 server IP (required with --subnet6)")
	fs.StringVar(&tunPrefix, "tun-prefix", "phose", "device-name prefix for per-client TUNs in multi-client mode")
	fs.Parse(args)

	cipher, err := packethose.ParseCipher(cf.encrypt)
	if err != nil {
		log.Fatal(err)
	}
	psk := parsePSK(cf.pskHex)
	if cipher != packethose.CipherNone && psk == nil {
		log.Fatalf("--encrypt %s requires --psk", cipher)
	}

	cfg := packethose.ServerConfig{
		Listen:     listen,
		PSK:        psk,
		AllowIP:    allow,
		MPTCP:      cf.mptcp,
		TuneSocket: brutalTuner(cf.brutalMbps),
	}

	multiClient := false
	if subnet != "" {
		pref, err := netip.ParsePrefix(subnet)
		if err != nil {
			log.Fatalf("--subnet: %v", err)
		}
		sIP, err := netip.ParseAddr(serverIP)
		if err != nil || !sIP.Is4() {
			log.Fatalf("--server-ip: must be a valid IPv4 address: %v", err)
		}
		cfg.Subnet = pref
		cfg.ServerIP = sIP
		multiClient = true
	}
	if subnet6 != "" {
		pref, err := netip.ParsePrefix(subnet6)
		if err != nil {
			log.Fatalf("--subnet6: %v", err)
		}
		sIP, err := netip.ParseAddr(serverIP6)
		if err != nil || !sIP.Is6() {
			log.Fatalf("--server-ip6: must be a valid IPv6 address: %v", err)
		}
		cfg.Subnet6 = pref
		cfg.ServerIP6 = sIP
		multiClient = true
	}
	if multiClient {
		cfg.TUNPrefix = tunPrefix
		cfg.VnetHdr = cf.vnetHdr
	} else {
		queues, ifname, err := packethose.OpenKernelTUN(cf.tun, cf.lanes, cf.vnetHdr)
		if err != nil {
			log.Fatalf("open tun: %v", err)
		}
		log.Printf("opened %d TUN queues on %s (vnet_hdr=%v)", cf.lanes, ifname, cf.vnetHdr)
		cfg.Lanes = cf.lanes
		cfg.Queues = queues
	}

	srv, err := packethose.NewServer(cfg)
	if err != nil {
		log.Fatalf("server: %v", err)
	}
	ctx, cancel := signalContext()
	defer cancel()
	if err := srv.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("server run: %v", err)
	}
	log.Printf("server exiting")
}

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	var (
		cf      commonFlags
		peer    string
		reqIP   string
		reqIP6  string
		autoIP  bool
	)
	bindCommon(fs, &cf)
	fs.StringVar(&peer, "peer", "", "TCP peer address:port (required)")
	fs.StringVar(&reqIP, "request-ip", "", "preferred IPv4 to ask the server for (multi-client mode)")
	fs.StringVar(&reqIP6, "request-ip6", "", "preferred IPv6 to ask the server for (multi-client mode)")
	fs.BoolVar(&autoIP, "auto-ip", false, "apply the server-assigned IP(s) to the TUN device automatically")
	fs.Parse(args)
	if peer == "" {
		log.Fatalf("--peer is required")
	}

	cipher, err := packethose.ParseCipher(cf.encrypt)
	if err != nil {
		log.Fatal(err)
	}
	psk := parsePSK(cf.pskHex)
	if cipher != packethose.CipherNone && psk == nil {
		log.Fatalf("--encrypt %s requires --psk", cipher)
	}

	queues, ifname, err := packethose.OpenKernelTUN(cf.tun, cf.lanes, cf.vnetHdr)
	if err != nil {
		log.Fatalf("open tun: %v", err)
	}
	log.Printf("opened %d TUN queues on %s (vnet_hdr=%v)", cf.lanes, ifname, cf.vnetHdr)

	var reqAddr4, reqAddr6 netip.Addr
	if reqIP != "" {
		reqAddr4, err = netip.ParseAddr(reqIP)
		if err != nil || !reqAddr4.Is4() {
			log.Fatalf("--request-ip: must be an IPv4 address: %v", err)
		}
	}
	if reqIP6 != "" {
		reqAddr6, err = netip.ParseAddr(reqIP6)
		if err != nil || !reqAddr6.Is6() {
			log.Fatalf("--request-ip6: must be an IPv6 address: %v", err)
		}
	}

	clicfg := packethose.ClientConfig{
		Peer:       peer,
		Lanes:      cf.lanes,
		Queues:     queues,
		PSK:        psk,
		Cipher:     cipher,
		MPTCP:      cf.mptcp,
		TuneSocket: brutalTuner(cf.brutalMbps),
		RequestIP:  reqAddr4,
		RequestIP6: reqAddr6,
	}
	if autoIP {
		clicfg.OnAssigned = func(a packethose.Assignment) {
			if err := exec.Command("ip", "link", "set", ifname, "up").Run(); err != nil {
				log.Printf("ip link set up: %v", err)
			}
			if a.HasV4() {
				cidr := fmt.Sprintf("%s/%d", a.V4Addr.String(), a.V4Prefix)
				log.Printf("server assigned %s (peer %s); configuring %s", cidr, a.V4Peer, ifname)
				if err := exec.Command("ip", "addr", "replace", cidr, "dev", ifname).Run(); err != nil {
					log.Printf("ip addr replace v4: %v", err)
				}
			}
			if a.HasV6() {
				cidr := fmt.Sprintf("%s/%d", a.V6Addr.String(), a.V6Prefix)
				log.Printf("server assigned %s (peer %s); configuring %s", cidr, a.V6Peer, ifname)
				if err := exec.Command("ip", "-6", "addr", "replace", cidr, "dev", ifname).Run(); err != nil {
					log.Printf("ip addr replace v6: %v", err)
				}
			}
		}
	}
	cli, err := packethose.NewClient(clicfg)
	if err != nil {
		log.Fatalf("client: %v", err)
	}
	ctx, cancel := signalContext()
	defer cancel()
	if err := cli.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("client run: %v", err)
	}
	log.Printf("client exiting")
}
