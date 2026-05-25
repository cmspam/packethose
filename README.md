# packethose

A framed-IP-over-TCP tunnel. It wraps raw IP packets in a 2-byte-length
TCP framing protocol and pairs with a virtual netdev so applications
see it as a normal interface.

Features include multi-lane outer connections, optional AEAD
encryption, optional tcp-brutal congestion control, a multi-client
server with per-client IP assignment, and a userspace gVisor netstack
mode for environments without CAP_NET_ADMIN. The kernel-TUN fast path
is Linux only. Userspace mode is Go-only and portable.

## Why

A surprising number of cloud and VPS providers cap UDP throughput well
below their advertised network speed. Common causes include virtio-net
descriptor limits, hypervisor offload mismatches, MAP-T BR queues, or
plain shaping on UDP that does not exist on TCP. The symptom is a 10
Gbps "unmetered" port that delivers 200 Mbps of UDP per flow and
multiple Gbps of TCP.

Packethose was written for that case. Wrapping the inner traffic in
TCP rides the host's TSO/GRO fast path and delivers multi-Gbps where
naive UDP tunnels stall. Multiple parallel TCP lanes spread per-flow
head-of-line blocking, give modern congestion control independent
windows to work with, and stay fast on lossy or reorder-heavy paths
where a single UDP/QUIC flow would back off.

Other situations where this shape is useful:

* **UDP-hostile networks.** Restrictive corporate proxies, hotel
  Wi-Fi, captive portals, and mobile carriers that shape or block UDP
  often allow ordinary TCP/443 flows freely while dropping or
  rate-limiting WireGuard, QUIC, and OpenVPN-UDP. Packethose is TCP
  all the way down. It looks like any other TCP flow to middleboxes.
* **Combining internet connections with MPTCP.** Pass `--mptcp` and
  the outer lane sockets become MPTCP. On a host with multiple
  uplinks such as LTE and Wi-Fi, two ISPs, or a bonded WAN, the
  kernel transparently spreads each lane across the available paths.
  The inner tunnel gets combined bandwidth and seamless failover
  without any tunnel-level logic. Pair `--mptcp` with `lanes: N` and
  you can saturate fairly asymmetric paths.

## Install

### Container

```bash
podman pull ghcr.io/cmspam/packethose:latest
# or
docker pull ghcr.io/cmspam/packethose:latest
```

### Binary

Grab `packethose-linux-amd64` or `packethose-linux-arm64` from the
[releases page](https://github.com/cmspam/packethose/releases). It
is statically linked and has no runtime dependencies.

### From source

```bash
git clone https://github.com/cmspam/packethose
cd packethose
go build -trimpath -ldflags='-s -w' -o packethose ./cmd/packethose
```

## Quick start

### Single-peer

```bash
# server
ip tuntap add ph0 mode tun multi_queue
ip link set ph0 up
ip addr add 10.66.0.1/24 dev ph0
./packethose server --listen 0.0.0.0:4500 --tun ph0 --lanes 4

# client
ip tuntap add ph0 mode tun multi_queue
ip link set ph0 up
ip addr add 10.66.0.2/24 dev ph0
./packethose client --peer <server-ip>:4500 --tun ph0 --lanes 4
```

`ping 10.66.0.1` from the client side and traffic flows through the
tunnel. Add iptables MASQUERADE on the server to route the tunnel
clients to the internet:

```bash
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s 10.66.0.0/24 -o eth0 -j MASQUERADE
```

### Authenticated and encrypted

```bash
# generate a PSK once and share it out of band
PSK=$(openssl rand -hex 32)

# both sides
./packethose server --listen 0.0.0.0:4500 --tun ph0 --lanes 4 \
  --psk "$PSK" --encrypt aes-gcm --allow <client-public-IP>

./packethose client --peer <server-ip>:4500 --tun ph0 --lanes 4 \
  --psk "$PSK" --encrypt aes-gcm
```

`aes-gcm` is the right default on modern x86 and ARM since AES-NI is
everywhere. `chacha20` is the fallback for hardware without AES
instructions.

### Multi-client server with server-allocated IPs

The server runs once. Multiple clients connect, each one gets its own
kernel TUN on the server side, and each one receives an address (IPv4,
IPv6, or both, depending on which subnets the server is configured
for). Allocation is sticky: the same `client_id` (random per client
process) gets the same address on reconnect.

```bash
# server (dual-stack pool: hand out one v4 and one v6 to each client)
./packethose server --listen "[::]:4500" \
  --subnet  10.66.0.0/24 --server-ip  10.66.0.1 \
  --subnet6 fd00:66::/64 --server-ip6 fd00:66::1 \
  --psk "$PSK" --encrypt aes-gcm --vnet_hdr

# enable forwarding and masquerade for both families
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
iptables  -t nat -A POSTROUTING -s 10.66.0.0/24 ! -d 10.66.0.0/24 -j MASQUERADE
ip6tables -t nat -A POSTROUTING -s fd00:66::/64 ! -d fd00:66::/64 -j MASQUERADE
iptables  -A FORWARD -s 10.66.0.0/24 -j ACCEPT
iptables  -A FORWARD -d 10.66.0.0/24 -j ACCEPT
ip6tables -A FORWARD -s fd00:66::/64 -j ACCEPT
ip6tables -A FORWARD -d fd00:66::/64 -j ACCEPT
```

`--subnet` and `--subnet6` are independent and either, both, or
neither may be set. With only one set, the server is single-family
multi-client. With both, it allocates dual-stack.

```bash
# client opts into auto IP. The server assigns; the client configures ph0.
ip tuntap add ph0 mode tun multi_queue
./packethose client --peer <server-ip>:4500 --tun ph0 --lanes 4 \
  --psk "$PSK" --encrypt aes-gcm --auto-ip
```

`--auto-ip` configures `ph0` with whichever address(es) the server
returned. The first v4 client receives `10.66.0.2`, the second
`10.66.0.3`, and so on. v6 addresses are hash-derived from the
client_id inside the subnet's host portion, so they spread out across
the prefix rather than running consecutively. Reconnecting clients
keep their previous address(es) (sticky by `client_id`) until the
session is collected after about 90 seconds of idle.

To request specific addresses from a pool, pass `--request-ip
10.66.0.10` and/or `--request-ip6 fd00:66::1234`. The server honors
each if it is free, otherwise it returns the next available value.

## IPv6

IPv6 is supported on three independent layers, each opt-in:

* **Inner traffic.** The tunnel ships whatever the kernel puts on the
  TUN. Assign both families to the device and IPv6 flows ride the
  tunnel alongside IPv4 with no extra configuration:

  ```bash
  ip tuntap add ph0 mode tun multi_queue
  ip link set ph0 up
  ip addr add 10.66.0.2/24 dev ph0
  ip -6 addr add fd00:66::2/64 dev ph0
  ```

* **Outer lane TCPs.** Listen on `[::]:4500` and the server accepts
  both families; clients can connect over either:

  ```bash
  # client over IPv6 outer
  ./packethose client --peer "[2001:db8::1]:4500" --tun ph0 --lanes 4 \
    --psk "$PSK" --encrypt aes-gcm

  # client over IPv4 outer to the same dual-stack server
  ./packethose client --peer 192.0.2.1:4500 --tun ph0 --lanes 4 \
    --psk "$PSK" --encrypt aes-gcm
  ```

* **Multi-client pool allocation.** Set `--subnet6`/`--server-ip6` on
  the server (with or without the IPv4 `--subnet`/`--server-ip`) and
  the server hands out a `/128` from the IPv6 prefix to each client,
  derived deterministically from its `client_id` so the spread inside
  the prefix is uniform and reconnects stick. `--auto-ip` on the
  client picks up whichever family the server gave it. See the
  multi-client section above for the full example.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--listen` (server) | `0.0.0.0:4500` | TCP listen `addr:port`. Use `[::]:port` for IPv6. |
| `--peer` (client) | (required) | TCP server `addr:port`. Use `[v6]:port` for IPv6. |
| `--tun` | `ph0` | TUN device name (multi-queue, created if absent). |
| `--lanes` | 4 | Parallel TCP connections. Inner flows hash to a lane. |
| `--psk` | (empty) | Pre-shared key hex (>= 16 bytes). Empty means no handshake. |
| `--encrypt` | `none` | AEAD: `none`, `aes-gcm`, `chacha20`. Requires `--psk`. |
| `--allow` (server) | (empty) | Restrict accept to one source IP. |
| `--vnet_hdr` | on | IFF_VNET_HDR for kernel GRO/GSO batching. |
| `--mptcp` | off | Enable MPTCP on the outer sockets. |
| `--brutal_mbps` | 0 | If non-zero, install tcp-brutal CC on lanes at this rate. |
| `--subnet` (server) | (empty) | Multi-client IPv4 pool, e.g. `10.66.0.0/24`. Requires `--psk`. |
| `--server-ip` (server) | (empty) | Server's IPv4 tunnel address; required with `--subnet`. |
| `--subnet6` (server) | (empty) | Multi-client IPv6 pool, e.g. `fd00:66::/64`. Requires `--psk`. |
| `--server-ip6` (server) | (empty) | Server's IPv6 tunnel address; required with `--subnet6`. |
| `--tun-prefix` (server) | `phose` | Per-client TUN name prefix in multi-client mode. |
| `--request-ip` (client) | (empty) | Preferred IPv4 from a multi-client server's pool. |
| `--request-ip6` (client) | (empty) | Preferred IPv6 from a multi-client server's pool. |
| `--auto-ip` (client) | off | Apply the server-assigned address(es) to the local TUN automatically. |

## YAML config

CLI flags continue to work. A YAML file is a shipping shape that
keeps a long argv off the systemd unit and lets you describe a
multi-user server in one place. Load with `--config /path/file.yaml`.
CLI flags that are set on the command line override any value the
YAML provides.

```yaml
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
  v6_subnet: fd00:66::/64
  server_ip4: 10.66.0.1
  server_ip6: fd00:66::1

users:
  - name: alice
    psk_hex: "deadbeef..."
    max_concurrent: 3
  - name: bob
    psk_hex: "cafef00d..."
    max_concurrent: 2
    reserved: [10.66.0.5, fd00:66::5]

forward:
  isolation: true
  masquerade: true
  tproxy: true
  tproxy_listen_port: 13338
  tproxy_fwmark: 0x1
  tproxy_table: 13338
  tun_match: "phose-*"
  egress_interface: ""    # empty: any non-phose-* output
```

### Forward posture

When the YAML `forward:` block requests any of isolation, masquerade,
or tproxy, the server installs a dedicated nftables table at startup
and removes it on shutdown:

```
table inet packethose {
  chain prerouting {              # when forward.tproxy
    iifname "phose-*" tproxy to :13338 meta mark set 0x1 accept
  }
  chain forward {                 # when forward.isolation
    iifname "phose-*" oifname "phose-*" drop
  }
  chain postrouting {              # when forward.masquerade
    iifname "phose-*" oifname != "phose-*" masquerade
  }
}
```

With `forward.tproxy: true`, the server also installs the matching
`ip rule add fwmark 0x1 lookup 13338` and `ip route add local default
dev lo table 13338` (v4 and v6 as configured) and runs the TPROXY
termination listener on port 13338. The listener accepts redirected
TCP and UDP flows, dials the original destination directly, and pairs
the sockets with `io.Copy` so Go's runtime drops into `splice()` for
TCP byte movement. UDP runs a per-flow demux with an IP_TRANSPARENT
reply socket so the client sees responses from the original
destination.

Inter-client isolation is enforced in two places: the nftables
forward chain (for ICMP and non-TPROXY'd traffic) and the TPROXY
listener's accept handler (TPROXY traffic bypasses the forward
chain). Both gates check the destination against the pool subnets.

Removing the YAML `forward:` block, or setting all of isolation,
masquerade, and tproxy to false, leaves packethose in pure-tunnel
mode: no nftables, no TPROXY listener, no policy routing.

### Per-user identity

A configured `users[]` block switches the server into multi-user
mode. Each user has its own PSK and an optional `max_concurrent`
quota. Reserved addresses are tied to one user; the pool refuses to
hand them to anybody else. The client sends its `--user NAME` in the
handshake and the server selects the matching PSK in O(1).

The legacy single-PSK server is still available: omit `users[]` and
set `server_psk` (or pass `--psk` on the command line).

### BBR

When `bbr: true` (the default), the server sets TCP_CONGESTION="bbr"
on every accepted and dialed outer socket. Kernels that do not list
bbr in `/proc/sys/net/ipv4/tcp_allowed_congestion_control` keep
whatever default they have; the option is best-effort and never
fails the connection.

## Wire protocol

### Default mode
```
[uint16 BE length][raw L3 packet][uint16 BE length][raw L3 packet]...
```

### `--vnet_hdr` mode (default)
```
[uint16 BE length][virtio_net_hdr (10 bytes, LE fields)][L3 packet]
```
Length includes the 10-byte vnet_hdr. The vnet_hdr carries GSO
metadata so the receiver can pass coalesced super-packets to the
kernel and let it segment on egress. Both peers must agree.

### Encryption (`--encrypt aes-gcm|chacha20`)
Each frame is wrapped by AEAD:
```
[uint16 BE length][AEAD ciphertext+tag]
```
Length is the ciphertext plus the 16-byte tag. The nonce is a
per-lane per-direction 64-bit counter. TCP keeps the endpoints in
lockstep so the counter does not appear on the wire.

### Handshake (when `--psk` is set, wire version 5)
Each address slot on the wire is 17 bytes: a 1-byte family tag (0,
4, or 6) followed by a 16-byte payload (IPv4 uses the first 4 bytes
and zero-pads the rest). The 16-byte `user_name` field is NUL-padded
text; an all-zero field selects the legacy single-PSK fallback when
the server has no `users[]` block.
```
client -> magic "PHOS"(4) || ver(1)=5 || cipher(1) || user_name(16)
       || nonce_c(32) || client_id(16) || lane_count(1)
       || req_v4(17) || req_v6(17)
server -> magic || ver || cipher
       || HMAC(psk, ver||cipher||user_name||nonce_c||client_id||lane_count||req_v4||req_v6)(32)
       || nonce_s(32)
       || asg_v4(17) || prefix_v4(1) || peer_v4(17)
       || asg_v6(17) || prefix_v6(1) || peer_v6(17)
client -> HMAC(psk, ver||cipher||user_name||nonce_s||asg_v4||prefix_v4||peer_v4||asg_v6||prefix_v6||peer_v6)(32)
```
Per-direction session keys are derived via HKDF-SHA256 over `(psk,
nonce_c || nonce_s)`. A family's `prefix` is zero when the server
did not assign that family. Single-peer servers leave both at zero
and the client uses its locally configured addresses.

## Always-on behaviour

Each lane runs under a supervisor that owns the TUN queue fd for the
lifetime of the process and cycles outer TCP sockets beneath it. On
any I/O error the connection is closed and reacquired with
exponential backoff (250 ms doubling to 30 s, with jitter). TCP
keepalive (`TCP_KEEPIDLE=15s`, `TCP_KEEPINTVL=5s`, `TCP_KEEPCNT=3`)
turns silent network outages into RSTs in about 30 seconds, rather
than waiting hours for the kernel default.

In effect, the tunnel feels like an ipip-style point-to-point. The
TUN interface stays up the whole time. When the peer goes away,
packets drop on the floor. When the peer returns, the lane
reconnects on its own. The process never exits of its own accord.

## tcp-brutal

If the [tcp-brutal](https://github.com/apernet/tcp-brutal) kernel
module is loaded on both endpoints, set `--brutal_mbps N` on both
sides to make each outer lane TCP run at a fixed rate of N Mbps.
This is useful on lossy paths where standard CC backs off too
aggressively.

## mihopium and mihomo integration

Packethose ships as a Go library
(`github.com/cmspam/packethose`) plus a CLI. The mihomo fork
[mihopium](https://github.com/cmspam/mihopium) imports it as a proxy
adapter:

```yaml
proxies:
  - name: tokyo
    type: packethose
    server: 1.2.3.4
    port: 4500
    lanes: 4
    psk: <hex>
    cipher: aes-gcm
    mtu: 1500
    # ip:  10.66.0.10/24      # optional: preferred IPv4 (server may assign)
    # ip6: fd00:66::10/64     # optional: preferred IPv6 (server may assign)
    # mode: native            # default: real kernel TUN, kernel-rate
    # mode: userspace         # alternative: gVisor netstack, no CAP_NET_ADMIN
    # interface-name: ph-tokyo
```

In `native` mode the adapter creates a real kernel TUN per proxy,
configures the server-assigned IP on it, and binds outbound sockets
to that interface via `SO_BINDTODEVICE`. Throughput approaches the
direct path (around 96% in benchmarks).

In `userspace` mode the adapter runs a gVisor netstack in-process.
No kernel TUN is needed. It is slower since the TCP/IP stack runs in
userspace, but it is useful when running many packethose proxies on
one host or in restricted environments.

The `dialer-proxy` field on the outbound is honored. Lane TCPs dial
through whatever mihomo chains them through.

## Container image

```bash
docker pull ghcr.io/cmspam/packethose:latest
docker run --rm --network host --cap-add NET_ADMIN \
  ghcr.io/cmspam/packethose:latest \
  server --listen 0.0.0.0:4500 --tun ph0 --lanes 4
```

Multi-arch: `linux/amd64`, `linux/arm64`.

## Performance

All numbers below are from a single cloud-host pair on the same
provider's internal network. Your path will differ. The point is
the relative cost of each option, not the absolute throughput.

Linux x86_64, MTU 1500, 8 iperf3 streams, 2 lanes:

| Configuration | Throughput |
|---|---:|
| baseline (no PSK, no encryption) | ~4.4 Gbps |
| PSK only (handshake, plaintext) | ~4.3 Gbps |
| PSK + AES-128-GCM | ~2.9 Gbps |
| PSK + ChaCha20-Poly1305 | ~2.0 Gbps |

AES-GCM costs roughly a third of the plaintext rate at this LAN
speed. ChaCha20 costs about half. Both run well above 1 Gbps
single-core on any modern x86 or ARM CPU, so on real internet paths
(typically a few hundred Mbps per flow) the crypto cost is
invisible.

A mihopium adapter on the kernel-TUN backend (`mode: native`)
reaches about 96% of the direct (non-tunnel) HTTPS download rate to
the same destination with AES-GCM enabled.

Multi-client server, two concurrent clients, AES-GCM, 4 lanes each:

| Client | Throughput |
|---|---:|
| client 1 to server | ~2.5 Gbps |
| client 2 to server | ~2.6 Gbps |
| aggregate through one server | ~5.1 Gbps |

## License

MIT.
