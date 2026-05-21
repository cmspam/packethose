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
	"strings"
	"sync"
	"syscall"
	"time"
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

  packethose server --listen ADDR:PORT --tun NAME --lanes N [--psk HEX] [--allow IP] [--mptcp]
  packethose client --peer ADDR:PORT  --tun NAME --lanes N [--psk HEX] [--mptcp]

Bring the TUN interface up + assign addresses externally:
  ip link set %s up
  ip addr add 10.55.0.1/24 dev %s
`, "tun0", "tun0")
}

type commonFlags struct {
	tun     string
	lanes   int
	pskHex  string
	mptcp   bool
	vnetHdr bool
	encrypt string
	cipher  cipherKind
}

func bindCommon(fs *flag.FlagSet, c *commonFlags) {
	fs.StringVar(&c.tun, "tun", "tun0", "TUN device name (multi-queue)")
	fs.IntVar(&c.lanes, "lanes", 2, "number of parallel TCP lanes")
	fs.StringVar(&c.pskHex, "psk", "", "pre-shared key (hex). empty = no handshake")
	fs.BoolVar(&c.mptcp, "mptcp", false, "enable MPTCP on outer sockets")
	fs.BoolVar(&c.vnetHdr, "vnet_hdr", false, "open TUN with IFF_VNET_HDR for GRO/GSO batching (Linux only)")
	fs.StringVar(&c.encrypt, "encrypt", "none", "AEAD cipher: none|aes-gcm|chacha20 (requires --psk)")
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

func openLanes(name string, n int, vnetHdr bool) []int {
	fds := make([]int, 0, n)
	var ifname string
	for i := 0; i < n; i++ {
		fd, nm, err := openTunQueueOpts(name, true, vnetHdr)
		if err != nil {
			log.Fatalf("open tun queue %d: %v", i, err)
		}
		if ifname == "" {
			ifname = nm
		}
		fds = append(fds, fd)
	}
	log.Printf("opened %d TUN queues on %s (vnet_hdr=%v)", n, ifname, vnetHdr)
	return fds
}

func dispatchLane(id, tunFd int, c net.Conn, cf *commonFlags, keys laneKeys) {
	if cf.vnetHdr {
		runLaneVnetHdr(id, tunFd, c, keys)
		return
	}
	runLane(id, tunFd, c, keys)
}

// ---- server ----

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

	ck, err := parseCipher(cf.encrypt)
	if err != nil {
		log.Fatal(err)
	}
	cf.cipher = ck
	psk := parsePSK(cf.pskHex)
	if ck != cipherNone && psk == nil {
		log.Fatalf("--encrypt %s requires --psk", ck)
	}
	fds := openLanes(cf.tun, cf.lanes, cf.vnetHdr)

	var lc net.ListenConfig
	if cf.mptcp {
		lc.SetMultipathTCP(true)
	}
	ctx, cancel := signalContext()
	defer cancel()
	ln, err := lc.Listen(ctx, "tcp", listen)
	if err != nil {
		log.Fatalf("listen %s: %v", listen, err)
	}
	log.Printf("listening on %s (mptcp=%v psk=%v allow=%s lanes=%d vnet_hdr=%v encrypt=%s)",
		listen, cf.mptcp, psk != nil, allow, cf.lanes, cf.vnetHdr, ck)

	type accepted struct {
		c    net.Conn
		keys laneKeys
	}
	conns := make(chan accepted, cf.lanes)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				log.Printf("accept: %v", err)
				return
			}
			if allow != "" {
				ip := remoteIP(c)
				if ip != allow {
					log.Printf("reject %s (allow=%s)", ip, allow)
					c.Close()
					continue
				}
			}
			keys, err := acceptHandshake(c, psk)
			if err != nil {
				log.Printf("handshake fail from %s: %v", c.RemoteAddr(), err)
				c.Close()
				continue
			}
			conns <- accepted{c, keys}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < cf.lanes; i++ {
		a := <-conns
		log.Printf("lane %d up: peer=%s cipher=%s", i, a.c.RemoteAddr(), a.keys.kind)
		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()
			dispatchLane(i, fds[i], a.c, &cf, a.keys)
		}()
	}
	wg.Wait()
	log.Printf("all lanes exited")
}

// ---- client ----

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

	ck, err := parseCipher(cf.encrypt)
	if err != nil {
		log.Fatal(err)
	}
	cf.cipher = ck
	psk := parsePSK(cf.pskHex)
	if ck != cipherNone && psk == nil {
		log.Fatalf("--encrypt %s requires --psk", ck)
	}
	fds := openLanes(cf.tun, cf.lanes, cf.vnetHdr)

	d := &net.Dialer{Timeout: 10 * time.Second}
	if cf.mptcp {
		d.SetMultipathTCP(true)
	}

	ctx, cancel := signalContext()
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < cf.lanes; i++ {
		c, err := d.DialContext(ctx, "tcp", peer)
		if err != nil {
			log.Fatalf("dial lane %d: %v", i, err)
		}
		keys, err := initiateHandshake(c, psk, ck)
		if err != nil {
			log.Fatalf("handshake lane %d: %v", i, err)
		}
		log.Printf("lane %d up: peer=%s cipher=%s", i, c.RemoteAddr(), keys.kind)
		wg.Add(1)
		i, c, k := i, c, keys
		go func() {
			defer wg.Done()
			dispatchLane(i, fds[i], c, &cf, k)
		}()
	}
	wg.Wait()
	log.Printf("all lanes exited")
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

func remoteIP(c net.Conn) string {
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return strings.TrimSpace(c.RemoteAddr().String())
	}
	return host
}
