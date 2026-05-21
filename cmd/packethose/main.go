package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"packethose"
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
  ip link set tun0 up
  ip addr add 10.55.0.1/24 dev tun0
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
	fs.StringVar(&c.tun, "tun", "tun0", "TUN device name (multi-queue)")
	fs.IntVar(&c.lanes, "lanes", 2, "number of parallel TCP lanes")
	fs.StringVar(&c.pskHex, "psk", "", "pre-shared key (hex). empty = no handshake")
	fs.BoolVar(&c.mptcp, "mptcp", false, "enable MPTCP on outer sockets")
	fs.BoolVar(&c.vnetHdr, "vnet_hdr", false, "open TUN with IFF_VNET_HDR for GRO/GSO batching (Linux only)")
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
		cf     commonFlags
		listen string
		allow  string
	)
	bindCommon(fs, &cf)
	fs.StringVar(&listen, "listen", "0.0.0.0:4500", "TCP listen address")
	fs.StringVar(&allow, "allow", "", "if set, only accept from this source IP")
	fs.Parse(args)

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

	srv, err := packethose.NewServer(packethose.ServerConfig{
		Listen:     listen,
		Lanes:      cf.lanes,
		Queues:     queues,
		PSK:        psk,
		AllowIP:    allow,
		MPTCP:      cf.mptcp,
		TuneSocket: brutalTuner(cf.brutalMbps),
	})
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
		cf   commonFlags
		peer string
	)
	bindCommon(fs, &cf)
	fs.StringVar(&peer, "peer", "", "TCP peer address:port (required)")
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

	cli, err := packethose.NewClient(packethose.ClientConfig{
		Peer:       peer,
		Lanes:      cf.lanes,
		Queues:     queues,
		PSK:        psk,
		Cipher:     cipher,
		MPTCP:      cf.mptcp,
		TuneSocket: brutalTuner(cf.brutalMbps),
	})
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
