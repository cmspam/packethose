# packethose

A framed-IP-over-TCP tunnel. It wraps raw IP packets in a 2-byte-length
TCP framing protocol and pairs with a virtual netdev so applications
see it as a normal interface.

Features include multi-lane outer connections, a forward-secret
authenticated handshake (Noise IK) with selectable AEAD, an always-on
handshake obfuscation envelope, accept-path rate limiting, UDP
acceleration (datagram batching plus kernel UDP segmentation offload),
optional tcp-brutal congestion control, a multi-client server with
per-client IP assignment and kernel-side byte accounting, and a
userspace gVisor netstack mode for environments without CAP_NET_ADMIN.
The kernel-TUN fast path is Linux only. Userspace mode is Go-only and
portable.

All of the security and abuse-control machinery lives in the
connection-setup path. The per-packet data path is a length-prefixed
frame and an AEAD seal, unchanged by any of it, so throughput is
unaffected.

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
  rate-limiting WireGuard, QUIC, and OpenVPN-UDP. Packethose is TCP all
  the way down, and in keyed mode the handshake is wrapped in a
  random-looking obfuscation envelope (see Obfuscation), so a passive
  middlebox sees an opaque TCP byte stream with no constant marker to
  fingerprint. This defeats passive protocol identification. It is not
  active-probe resistant and does not mimic TLS: against an adversary
  that actively probes endpoints (e.g. the GFW), run the outer lanes
  through a censorship-resistant proxy via the `Dialer` hook rather
  than relying on the envelope alone.
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

Authentication uses static X25519 keypairs, WireGuard-style: each side
has a keypair and is configured with the other side's public key. The
handshake is Noise IK, which gives mutual authentication and forward
secrecy; the transport is AEAD. Generate keys with `genkey` / `pubkey`:

```bash
# on each host, once
./packethose genkey > key            # private key
./packethose pubkey < key            # its public key (share this out of band)

# server: knows its own key and the client's public key
./packethose server --listen 0.0.0.0:4500 --tun ph0 --lanes 4 \
  --key @server.key --peer-key <client-public-key> --encrypt aes-gcm

# client: knows its own key and the server's public key
./packethose client --peer <server-ip>:4500 --tun ph0 --lanes 4 \
  --key @client.key --peer-key <server-public-key> --encrypt aes-gcm
```

`@server.key` reads the key from a file; a bare base64/hex value works
too. `aes-gcm` is the right default on modern x86 and ARM since AES-NI
is everywhere; `chacha20` is the fallback for hardware without AES
instructions. Both ends must select the same suite. Forward secrecy
means a later compromise of a static key does not decrypt recorded
sessions. See [SPEC.md](SPEC.md) for the full handshake.

### Multi-client server with server-allocated IPs

The server runs once. Multiple clients connect, each authorized by its
static public key, and each receives an address (IPv4, IPv6, or both,
depending on which subnets the server is configured for). Allocation is
sticky: a client's identity (its static key) gets the same address on
reconnect. Authorize many clients via the YAML `users:` block (see YAML
config); the single-`--peer-key` form below authorizes exactly one.

```bash
# server (dual-stack pool: hand out one v4 and one v6 to each client)
./packethose server --listen "[::]:4500" \
  --subnet  10.66.0.0/24 --server-ip  10.66.0.1 \
  --subnet6 fd00:66::/64 --server-ip6 fd00:66::1 \
  --key @server.key --peer-key <client-public-key> --encrypt aes-gcm --vnet_hdr

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
  --key @client.key --peer-key <server-public-key> --encrypt aes-gcm --auto-ip
```

`--auto-ip` configures `ph0` with whichever address(es) the server
returned. The first v4 client receives `10.66.0.2`, the second
`10.66.0.3`, and so on. v6 addresses are derived from the client's
identity inside the subnet's host portion, so they spread out across
the prefix rather than running consecutively. Reconnecting clients
keep their previous address(es) (sticky by static key) until the
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
    --key @client.key --peer-key <server-public-key> --encrypt aes-gcm

  # client over IPv4 outer to the same dual-stack server
  ./packethose client --peer 192.0.2.1:4500 --tun ph0 --lanes 4 \
    --key @client.key --peer-key <server-public-key> --encrypt aes-gcm
  ```

* **Multi-client pool allocation.** Set `--subnet6`/`--server-ip6` on
  the server (with or without the IPv4 `--subnet`/`--server-ip`) and
  the server hands out a `/128` from the IPv6 prefix to each client,
  derived deterministically from its identity so the spread inside
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
| `--key` | (empty) | This node's static private key (base64/hex, or `@FILE`). Empty means open mode (no handshake, no encryption). |
| `--peer-key` | (empty) | Peer's static public key: the server's key on a client; the one authorized client key on a single-peer server. |
| `--encrypt` | `aes-128-gcm` | Transport cipher: `aes-128-gcm` (default, fastest), `aes-256-gcm`, or `chacha20`. Both ends must match. |
| `--allow` (server) | (empty) | Restrict accept to one source IP. |
| `--metrics` (server) | (empty) | `addr:port` for Prometheus `/metrics` and `/healthz`. |
| `--vnet_hdr` | on | IFF_VNET_HDR for kernel GRO/GSO batching. |
| `--mptcp` | off | Enable MPTCP on the outer sockets. |
| `--brutal_mbps` | 0 | If non-zero, install tcp-brutal CC on lanes at this rate. |
| `--subnet` (server) | (empty) | Multi-client IPv4 pool, e.g. `10.66.0.0/24`. Requires `--key`. |
| `--server-ip` (server) | (empty) | Server's IPv4 tunnel address; required with `--subnet`. |
| `--subnet6` (server) | (empty) | Multi-client IPv6 pool, e.g. `fd00:66::/64`. Requires `--key`. |
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

# The server's static private key (base64). Its public half is what you
# hand to clients as their --peer-key. Generate with `packethose genkey`.
server_private_key: "..."

# Accept-path abuse controls. Omitted fields take built-in defaults
# (per_ip_per_sec 10, per_ip_burst 20, max_in_flight 256). Defaults
# apply even if this block is absent; set disabled: true to turn off.
rate_limit:
  per_ip_per_sec: 10
  per_ip_burst: 20
  max_in_flight: 256

brutal:
  enabled: false
  rate_mbps: 0

pool:
  v4_subnet: 10.66.0.0/24
  v6_subnet: fd00:66::/64
  server_ip4: 10.66.0.1
  server_ip6: fd00:66::1

# Authorized clients, by static public key. SIGHUP reloads this list
# without dropping live sessions. (A single-peer server can instead set
# peer_public_key.)
users:
  - name: alice
    public_key: "kZ...="
    max_concurrent: 3
  - name: bob
    public_key: "9p...="
    max_concurrent: 2
    reserved: [10.66.0.5, fd00:66::5]

forward:
  isolation: true
  masquerade: true
  tproxy: true
  metering: true          # per-client kernel byte counters (see Metering)
  tproxy_listen_port: 13338
  tproxy_fwmark: 0x1
  tproxy_table: 13338
  tun_match: "phose-*"
  egress_interface: ""    # empty: any non-phose-* output
```

### Forward posture

When the YAML `forward:` block requests any of isolation, masquerade,
tproxy, or metering, the server installs a dedicated nftables table at
startup and removes it on shutdown:

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

A configured `users[]` block switches the server into multi-client
mode. Each user is identified by its static public key and has an
optional `max_concurrent` quota. Reserved addresses are tied to one
user; the pool refuses to hand them to anybody else. The handshake
delivers the client's public key (the Noise IK `s` token) and the
server authorizes it in O(1). A single-peer server can instead set one
`peer_public_key` / `--peer-key`.

`SIGHUP` reloads the `users:` list from the config file without
dropping live sessions: a provider can add or revoke client keys, or
change quotas, on a running server. (Pool reservations are fixed at
startup.)

### BBR

When `bbr: true` (the default), the server sets TCP_CONGESTION="bbr"
on every accepted and dialed outer socket. Kernels that do not list
bbr in `/proc/sys/net/ipv4/tcp_allowed_congestion_control` keep
whatever default they have; the option is best-effort and never
fails the connection.

### Rate limiting

The server gates new connections before the handshake runs. A
per-source-IP token bucket throttles how fast one address can open
connections, and a server-wide semaphore caps how many handshakes are
in flight at once, bounding goroutines and CPU under a flood. The
per-IP table is bounded and self-pruning. All checks are on the accept
path; none touch the data path. Defaults are applied even when the
`rate_limit:` block is absent; set `disabled: true` to turn it off.

### Metering

With `forward.metering: true` (multi-client mode), the server adds
per-client byte counters to its nftables table, keyed on each client's
pool address and hooked at prerouting and postrouting. Counting happens
in the kernel, so it is free on the data path and captures both
forwarded and TPROXY-terminated traffic. This is the same shape as
reading WireGuard's per-peer transfer counters. Read them with
`nft -j list set inet packethose acct_up4` (and `acct_down4`,
`acct_up6`, `acct_down6`), or programmatically via the library's
`NFTInstaller.Stats()`.

### Metrics and health

Pass `--metrics 127.0.0.1:9090` (server) to expose a read-only HTTP
endpoint with Prometheus `/metrics` and a `/healthz` check. Metrics
cover accepts, handshake outcomes, rate-limit and slot-exhaustion
drops, active sessions, and per-client byte totals (from the kernel
counters above). Reading them does not touch the data path.

## Wire protocol

The authoritative, implementation-independent description is in
[SPEC.md](SPEC.md). This section is a summary.

### Frame format
```
[type:1][uint16 BE length][payload]
```
`type` is 0 for a single inner unit or 1 for a batch (several inner
units, each 16-bit-length-prefixed, coalesced into one frame). In keyed
mode the payload is AEAD ciphertext — the transport cipher selected by
`--encrypt` (AES-128-GCM by default; AES-256-GCM or ChaCha20-Poly1305
optional), with keys derived from the Noise handshake. The per-lane
per-direction counter nonce is kept in lockstep by in-order TCP and
never sent; the tag is 16 bytes. In open mode the payload is plaintext.

An inner unit is one L3 packet, or — in `--vnet_hdr` mode (default) — a
10-byte `virtio_net_hdr` (GSO metadata) followed by an L3 super-packet,
so the kernel hands over and accepts coalesced TCP super-packets.

### UDP acceleration (batching + USO)
Small-datagram UDP is packet-rate-bound where TCP is GSO-coalesced. Two
Linux mechanisms narrow the gap: **batching** packs a burst of already-
queued datagrams into one frame (one seal, one write), done
opportunistically so a lone packet is never delayed to fill a batch; and
**USO** (negotiated, kernel >= ~6.2) lets the kernel coalesce and
re-segment same-flow UDP the way it does TCP. Both ride the TCP wire and
fall back gracefully where unsupported. See [SPEC.md](SPEC.md).

### Handshake (keyed mode)

The handshake is **Noise IK** (`Noise_IK_25519_AESGCM_SHA256` or
`...ChaChaPoly...`), the same pattern WireGuard uses: mutual
authentication by static X25519 keys plus an ephemeral exchange for
forward secrecy. Two messages: the client sends its ephemeral, its
(encrypted) static key, and a request payload; the server replies with
its ephemeral and the address assignment. The server authorizes the
client's static public key before allocating any address, so an
unauthorized peer can never drive a pool allocation. The cipher suite
is fixed by configuration and not negotiated in band; both ends must
match.

### Obfuscation envelope (always on in keyed mode)

Each handshake message (the raw Noise bytes) is wrapped as:
```
[random salt(16)][ChaCha20( u16 body_len || u16 pad_len || body || random-pad )]
```
The ChaCha20 keystream is keyed by `HKDF(server_public_key, salt)`. The
salt is fresh per message and the encrypted region is indistinguishable
from random without the key, so there is no constant marker and no
fixed length to fingerprint. The client already knows the server's
public key (it is the Noise IK pre-known key), so no extra secret is
needed. Obfuscation is camouflage only: it defeats passive
fingerprinting but is not active-probe resistant, and anyone holding
the server's public key can de-obfuscate. The data path is never
enveloped, so throughput is unchanged. Full details in
[SPEC.md](SPEC.md).

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

## Use as a Go library

Packethose ships as a Go library (`github.com/cmspam/packethose`)
plus a CLI. The client side dials its outer lane sockets through a
pluggable `ContextDialer`, so an embedding program can route the
lanes through its own proxy chain or a bound interface.

Two backends are available. The native backend creates a real kernel
TUN and reaches close to the direct path. The userspace backend runs
a gVisor netstack in-process and needs no `CAP_NET_ADMIN`, at the
cost of running the TCP/IP stack in userspace. It is useful when
running many instances on one host or in restricted environments.

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
| open mode (no encryption) | ~4.4 Gbps |
| keyed, AES-128-GCM | ~2.9 Gbps |
| keyed, ChaCha20-Poly1305 | ~2.0 Gbps |

AES-GCM costs roughly a third of the plaintext rate at this LAN
speed. ChaCha20 costs about half. The AEAD is the same primitive
whether driven by the older framing or the Noise transport, so these
are unchanged by v7. Both run well above 1 Gbps single-core on any
modern x86 or ARM CPU, so on real internet paths (typically a few
hundred Mbps per flow) the crypto cost is invisible.

Multi-client server, two concurrent clients, AES-GCM, 4 lanes each:

| Client | Throughput |
|---|---:|
| client 1 to server | ~2.5 Gbps |
| client 2 to server | ~2.6 Gbps |
| aggregate through one server | ~5.1 Gbps |

## License

MIT.
