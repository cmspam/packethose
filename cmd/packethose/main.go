package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strings"
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
	case "genkey":
		runGenKey()
	case "pubkey":
		runPubKey()
	default:
		usage()
		os.Exit(2)
	}
}

// runGenKey prints a fresh static private key (base64) to stdout.
func runGenKey() {
	priv, _, err := packethose.GenerateKeypair()
	if err != nil {
		log.Fatalf("genkey: %v", err)
	}
	fmt.Println(packethose.FormatKey(priv))
}

// runPubKey reads a private key (base64/hex) from stdin and prints its
// public key, mirroring `wg pubkey`.
func runPubKey() {
	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("pubkey: read stdin: %v", err)
	}
	priv, err := packethose.ParseKey(strings.TrimSpace(string(in)))
	if err != nil {
		log.Fatalf("pubkey: %v", err)
	}
	pub, err := packethose.PublicFromPrivate(priv)
	if err != nil {
		log.Fatalf("pubkey: %v", err)
	}
	fmt.Println(packethose.FormatKey(pub))
}

func usage() {
	fmt.Fprintf(os.Stderr, `packethose: userspace TUN + multi-lane TCP/MPTCP tunnel

  packethose server --listen ADDR:PORT --tun NAME --lanes N [flags]
  packethose client --peer ADDR:PORT  --tun NAME --lanes N [flags]
  packethose genkey                    print a new static private key
  packethose pubkey                    read a private key on stdin, print its public key

Common flags:
  --key KEY            this node's static private key (base64/hex, or @FILE). empty = open mode
  --peer-key KEY       peer static public key: server's key on the client,
                       the authorized client key on a single-peer server
  --encrypt CIPHER     aes-gcm | chacha20 (the Noise suite; both ends must match)
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
	tun        string
	lanes      int
	key        string
	peerKey    string
	mptcp      bool
	vnetHdr    bool
	encrypt    string
	brutalMbps int
}

func bindCommon(fs *flag.FlagSet, c *commonFlags) {
	fs.StringVar(&c.tun, "tun", "ph0", "TUN device name (multi-queue)")
	fs.IntVar(&c.lanes, "lanes", 4, "number of parallel TCP lanes")
	fs.StringVar(&c.key, "key", "", "this node's static private key (base64/hex, or @FILE). empty = open mode")
	fs.StringVar(&c.peerKey, "peer-key", "", "peer static public key (server key on the client; authorized client key on a single-peer server)")
	fs.BoolVar(&c.mptcp, "mptcp", false, "enable MPTCP on outer sockets")
	// vnet_hdr is the fast path on Linux (GRO/GSO super-packets). On by
	// default; opt out with --vnet_hdr=false for very old kernels lacking
	// IFF_VNET_HDR support.
	c.vnetHdr = true
	fs.BoolVar(&c.vnetHdr, "vnet_hdr", true, "open TUN with IFF_VNET_HDR for GRO/GSO batching (default on, Linux only)")
	fs.StringVar(&c.encrypt, "encrypt", "aes-gcm", "Noise AEAD suite: aes-gcm|chacha20 (both ends must match)")
	fs.IntVar(&c.brutalMbps, "brutal_mbps", 0, "if non-zero, configure tcp-brutal CC on lanes at this Mbps")
}

func brutalTuner(mbps int) func(net.Conn) {
	if mbps <= 0 {
		return nil
	}
	rate := uint64(mbps) * 1_000_000 / 8
	return packethose.BrutalTuner(rate, 0, log.Printf)
}

// readKeyArg returns the literal value, or the file contents when the
// argument is "@/path/to/file".
func readKeyArg(s string) string {
	if strings.HasPrefix(s, "@") {
		b, err := os.ReadFile(s[1:])
		if err != nil {
			log.Fatalf("read key file %s: %v", s[1:], err)
		}
		return strings.TrimSpace(string(b))
	}
	return s
}

func parseKey(s string) []byte {
	if s == "" {
		return nil
	}
	b, err := packethose.ParseKey(readKeyArg(s))
	if err != nil {
		log.Fatalf("key: %v", err)
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
		cf          commonFlags
		listen      string
		allow       string
		subnet      string
		serverIP    string
		subnet6     string
		serverIP6   string
		tunPrefix   string
		configPath  string
		metricsAddr string
	)
	bindCommon(fs, &cf)
	fs.StringVar(&listen, "listen", "", "TCP listen address (default 0.0.0.0:4500)")
	fs.StringVar(&allow, "allow", "", "if set, only accept from this source IP")
	fs.StringVar(&metricsAddr, "metrics", "", "addr:port for Prometheus /metrics and /healthz (off by default)")
	fs.StringVar(&subnet, "subnet", "", "multi-client IPv4 subnet (CIDR, e.g. 10.66.0.0/24); requires --key")
	fs.StringVar(&serverIP, "server-ip", "", "multi-client tunnel-side IPv4 server IP (required with --subnet)")
	fs.StringVar(&subnet6, "subnet6", "", "multi-client IPv6 subnet (CIDR, e.g. fd00:66::/64); requires --key")
	fs.StringVar(&serverIP6, "server-ip6", "", "multi-client tunnel-side IPv6 server IP (required with --subnet6)")
	fs.StringVar(&tunPrefix, "tun-name", "", "name of the shared TUN device in multi-client mode (default phose0)")
	fs.StringVar(&configPath, "config", "", "path to YAML config (overlays beneath CLI flags)")
	fs.Parse(args)

	cipher, err := packethose.ParseCipher(cf.encrypt)
	if err != nil {
		log.Fatal(err)
	}

	cfg := packethose.ServerConfig{
		Listen:           listen,
		StaticPrivateKey: parseKey(cf.key),
		PeerPublicKey:    parseKey(cf.peerKey),
		Cipher:           cipher,
		AllowIP:          allow,
		MetricsAddr:      metricsAddr,
		MPTCP:            cf.mptcp,
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
	if tunPrefix != "" {
		cfg.TUNName = tunPrefix
	}

	fileCfg, err := packethose.LoadFile(configPath)
	if err != nil {
		log.Fatal(err)
	}
	if err := fileCfg.ApplyServer(&cfg); err != nil {
		log.Fatalf("apply config: %v", err)
	}
	if cfg.Listen == "" {
		cfg.Listen = "0.0.0.0:4500"
	}
	if cfg.Subnet.IsValid() || cfg.Subnet6.IsValid() {
		multiClient = true
	}
	if cfg.TUNName == "" {
		cfg.TUNName = "phose0"
	}

	// Phase A wires BBR per accepted socket. brutal_mbps still
	// overrides per-socket congestion control when requested.
	tunes := []func(net.Conn){}
	wantBBR := fileCfg.WantBBR()
	if wantBBR {
		tunes = append(tunes, packethose.BBRTuner())
	}
	if t := brutalTuner(cf.brutalMbps); t != nil {
		tunes = append(tunes, t)
	} else if fileCfg.Brutal.Enabled && fileCfg.Brutal.RateMbps > 0 {
		tunes = append(tunes, brutalTuner(fileCfg.Brutal.RateMbps))
	}
	cfg.TuneSocket = composeTuners(tunes)

	if !multiClient {
		queues, ifname, err := packethose.OpenKernelTUN(cf.tun, cf.lanes, cf.vnetHdr)
		if err != nil {
			log.Fatalf("open tun: %v", err)
		}
		log.Printf("opened %d TUN queues on %s (vnet_hdr=%v)", cf.lanes, ifname, cf.vnetHdr)
		cfg.Lanes = cf.lanes
		cfg.Queues = queues
	} else if !cfg.VnetHdr {
		cfg.VnetHdr = cf.vnetHdr
	}

	srv, err := packethose.NewServer(cfg)
	if err != nil {
		log.Fatalf("server: %v", err)
	}
	if wantBBR && !packethose.BBRAvailable() {
		log.Printf("warn: BBR requested but not in tcp_allowed_congestion_control; running with kernel default")
	}
	ctx, cancel := signalContext()
	defer cancel()

	// SIGHUP reloads the authorized-client set from the YAML config
	// without dropping live sessions.
	if configPath != "" {
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-hup:
					fc, err := packethose.LoadFile(configPath)
					if err != nil {
						log.Printf("reload: %v", err)
						continue
					}
					users, err := fc.ToUsers()
					if err != nil {
						log.Printf("reload users: %v", err)
						continue
					}
					if err := srv.ReloadUsers(users); err != nil {
						log.Printf("reload apply: %v", err)
					}
				}
			}
		}()
	}

	if err := srv.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("server run: %v", err)
	}
	log.Printf("server exiting")
}

func composeTuners(tunes []func(net.Conn)) func(net.Conn) {
	if len(tunes) == 0 {
		return nil
	}
	if len(tunes) == 1 {
		return tunes[0]
	}
	return func(c net.Conn) {
		for _, t := range tunes {
			if t != nil {
				t(c)
			}
		}
	}
}

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	var (
		cf     commonFlags
		peer   string
		reqIP  string
		reqIP6 string
		autoIP bool
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

	tunes := []func(net.Conn){packethose.BBRTuner()}
	if t := brutalTuner(cf.brutalMbps); t != nil {
		tunes = append(tunes, t)
	}
	clicfg := packethose.ClientConfig{
		Peer:             peer,
		Lanes:            cf.lanes,
		Queues:           queues,
		StaticPrivateKey: parseKey(cf.key),
		PeerPublicKey:    parseKey(cf.peerKey),
		Cipher:           cipher,
		MPTCP:            cf.mptcp,
		TuneSocket:       composeTuners(tunes),
		RequestIP:        reqAddr4,
		RequestIP6:       reqAddr6,
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
