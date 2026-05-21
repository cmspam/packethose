# packethose

A framed-IP-over-TCP tunnel: wraps raw IP packets in a 2-byte-length TCP
framing protocol and pairs with a virtual netdev so applications see it
as a normal interface.

## Why

On constrained UDP paths (e.g. virtio-net descriptor caps inside VMs),
wrapping inner traffic in TCP rides the host's TSO/GRO fast path and
delivers multi-Gbps where naive UDP tunnels stall well below 1 Gbps.

## Wire protocol

### Default mode
```
[uint16 BE length][raw L3 packet][uint16 BE length][raw L3 packet]...
```
Inner IP version (4/6) is detected from the first nibble. Packets are
written directly to the TUN device.

### `--vnet_hdr` mode (recommended for low MTU)
```
[uint16 BE length][virtio_net_hdr (10 bytes, LE fields)][L3 packet]
```
Length includes the 10-byte vnet_hdr. The vnet_hdr carries GSO metadata
so the receiver can pass coalesced super-packets to the kernel and let
it segment on egress. Both peers must run in the same mode.

### Encryption (`--encrypt aes-gcm|chacha20`)
With encryption, each frame's payload is wrapped by AEAD:
```
[uint16 BE length][AEAD ciphertext+tag]
```
Length is the ciphertext+tag length. Nonce is a per-lane per-direction
64-bit counter; TCP keeps the endpoints in lockstep so the counter does
not appear on the wire. Requires `--psk`.

### Handshake (when `--psk` is set)
```
client -> magic(4) || ver(1)=2 || cipher(1) || nonce_c(32)
server -> magic(4) || ver(1)=2 || cipher(1) || HMAC(psk, ver||cipher||nonce_c)(32) || nonce_s(32)
client -> HMAC(psk, ver||cipher||nonce_s)(32)
```
Per-direction session keys are derived via HKDF-SHA256 over
`(psk, nonce_c || nonce_s)`.

## Build

```bash
GOOS=linux GOARCH=amd64 GOAMD64=v3 CGO_ENABLED=0 \
  go build -buildvcs=false -ldflags="-s -w" -o packethose .
```

## Run

```bash
# pre-create the TUN device on each side
ip tuntap add tt0 mode tun multi_queue
ip link set tt0 up
ip link set tt0 mtu 1500
ip addr add 10.66.0.1/24 dev tt0   # or .2 on the client side

# server
./packethose server --listen 0.0.0.0:4500 --tun tt0 --lanes 4 --vnet_hdr

# client
./packethose client --peer <server-ip>:4500 --tun tt0 --lanes 4 --vnet_hdr
```

For hardened deployments add `--psk <hex>` and `--encrypt aes-gcm` on
both peers, and `--allow <client-IP>` on the server.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--listen` (server) | `0.0.0.0:4500` | TCP listen `addr:port`. Use `[::]:port` for IPv6. |
| `--peer` (client) | (required) | TCP server `addr:port`. Use `[v6]:port` for IPv6. |
| `--tun` | `tun0` | TUN device name (created if absent). |
| `--lanes` | 2 | Parallel TCP connections. Inner flows hash to a lane. |
| `--psk` | (empty) | Pre-shared key hex (>= 16 bytes). Empty disables handshake. |
| `--allow` (server) | (empty) | Restrict accept to one source IP. |
| `--mptcp` | false | Enable MPTCP on the outer sockets. |
| `--vnet_hdr` | false | Use IFF_VNET_HDR passthrough (low-MTU big win). |
| `--encrypt` | none | AEAD cipher: `none`, `aes-gcm`, `chacha20`. Requires `--psk`. |

## Performance

| Path | MTU | Mode | Throughput |
|---|---|---|---|
| LAN (dp ↔ lw) | 1500 | `--vnet_hdr`, plain | 4.38 Gbps (8 stream) |
| LAN | 1500 | `--vnet_hdr` + aes-gcm | 2.88 Gbps |
| LAN | 1500 | `--vnet_hdr` + chacha20 | 1.96 Gbps |
| Internet (~9 ms) | 1500 | `--vnet_hdr`, plain | ~600 Mbps real-world |
| Internet | 1500 | `--vnet_hdr` + aes-gcm | ~600 Mbps real-world |

`aes-gcm` is preferred when both endpoints have AES-NI (every modern
x86/ARM CPU); `chacha20` is the fallback for hardware without it.
