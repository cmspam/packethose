# Packethose protocol specification (v7)

This document specifies the packethose wire protocol precisely enough to
build or audit an independent implementation. It describes the v7
protocol: a Noise IK static-key handshake wrapped in an obfuscation
envelope, followed by a length-prefixed AEAD transport, spread across
one or more parallel TCP lanes.

All multi-byte integers are big-endian unless stated otherwise.

## 1. Overview

A packethose session carries raw L3 packets between two endpoints. The
inner traffic is whatever the peers put on their TUN devices; packethose
does not inspect or modify it beyond framing.

A session is composed of `N` independent **lanes**. Each lane is one TCP
(optionally MPTCP) connection that runs its own complete handshake and
its own transport state. Lanes belonging to one client are grouped by
the client's identity. Inner flows are hashed to a lane by the sender;
the protocol does not require any particular hashing.

Two modes exist:

* **Keyed mode** (the normal mode): both endpoints have X25519 static
  keypairs, the handshake runs, and the transport is encrypted and
  authenticated.
* **Open mode**: no keys are configured, no handshake runs, and frames
  are sent in plaintext. Open mode is for trusted point-to-point links
  and has no security properties. The rest of this document describes
  keyed mode unless noted.

## 2. Identity and keys

Every endpoint has an X25519 static keypair. The 32-byte public key is
the endpoint's identity.

* A client is configured with its own static private key and the
  server's static public key.
* A server is configured with its own static private key and the set of
  authorized client public keys (one, for single-peer; many, for
  multi-client).

A client's 16-byte **session id** is `SHA-256(client_public_key)[0:16]`.
The server uses it to group a client's lanes and to key sticky address
allocation. It is derived, never transmitted.

Keys are encoded on disk as standard base64 (WireGuard-style); hex is
also accepted on input.

## 3. Cryptographic handshake

The handshake is the Noise pattern **IK** with one of:

* `Noise_IK_25519_AESGCM_SHA256`
* `Noise_IK_25519_ChaChaPoly_SHA256`

The cipher suite is fixed by configuration and is **not** negotiated in
band; both endpoints must be configured identically, as in WireGuard. A
mismatch causes the handshake to fail.

The Noise prologue is the ASCII bytes `packethose-v7` on both sides.

IK exchanges two messages:

```
initiator -> responder:  e, es, s, ss   + payload1
responder -> initiator:  e, ee, se      + payload2
```

The client is the initiator and knows the server's static public key in
advance (the IK pre-message `s`). After the responder processes the
first message it has authenticated the initiator's static key (the
message payload's AEAD tag verifies only if the initiator holds the
private key matching the static key it presented). The server MUST
authorize that key (section 5) before processing `payload1` for
allocation.

On completion both sides obtain two directional transport keys via the
standard Noise `Split()` (initiator-to-responder and
responder-to-initiator). Each is run through
`HKDF-SHA256(info = "packethose-transport-v7")` to the selected cipher's
key length, and the **data path uses those keys with packethose's own
framed AEAD (section 7), not Noise's transport ciphers.** This is
deliberate: it lets the transport run AES-**128**-GCM (the default),
whereas the Noise handshake suite mandates AES-256-GCM. AES-128 is
materially faster on AES-NI and the handshake's stronger suite costs
nothing because it runs once per connection.

The data-path cipher is selected by configuration and announced in
`payload1` (below); the server rejects a mismatch. Options:

* `aes-128-gcm` (default): Noise handshake over AES-256-GCM, transport
  over AES-128-GCM.
* `aes-256-gcm`: AES-256-GCM for both.
* `chacha20` (ChaCha20-Poly1305): for hardware without AES instructions;
  same 256-bit key in handshake and transport.

### 3.1 Handshake payloads

`payload1` (client to server), `clientPayloadLen` = 38 bytes:

```
ver(1) = 7
cipher(1)          # data-path cipher: 1=AES-128-GCM, 2=ChaCha20-Poly1305, 3=AES-256-GCM
lane_count(1)
req_v4(17)         # requested IPv4 address slot (section 6)
req_v6(17)         # requested IPv6 address slot
flags(1)           # bit0 = USO-capable (section 9)
```

`payload2` (server to client), `serverPayloadLen` = 72 bytes:

```
ver(1) = 7
asg_v4(17)         # assigned IPv4 slot
prefix_v4(1)       # 0 = no IPv4 assignment
peer_v4(17)        # server tunnel IPv4
asg_v6(17)
prefix_v6(1)
peer_v6(17)
flags(1)           # bit0 = USO-capable (section 9)
```

A receiver MUST reject a payload whose `ver` byte is not 7. The server
rejects a `payload1` whose `cipher` differs from its own configured
cipher. The `flags` exchange negotiates UDP segmentation offload: it is
used only if both peers set bit0 (section 9).

## 4. Obfuscation envelope

Each handshake message (the raw Noise message bytes) is wrapped before
transmission. Open mode does not use the envelope.

The envelope key is `HKDF-SHA256(ikm = server_static_public_key, salt =
nil, info = "packethose-obfs-v7-key")`, truncated to 32 bytes. Both
endpoints can compute it: the client knows the server's public key, the
server knows its own. The envelope is camouflage only; it is not an
authentication boundary, and an adversary holding the server's public
key can remove it.

Wire format of one enveloped message:

```
salt(16)                      # random, cleartext
ChaCha20( body_len(2) || pad_len(2) || body || pad )
```

The ChaCha20 key and 12-byte nonce are
`HKDF-SHA256(ikm = envelope_key, salt = salt, info =
"packethose-obfs-v7")`, reading 44 bytes (32 key, 12 nonce). The
keystream covers the 4-byte length header, the body, and the padding as
one continuous stream. `pad_len` is a uniformly random 0..255. The
receiver reads the salt, derives the cipher, decrypts the 4-byte header
to learn `body_len` and `pad_len`, then reads and decrypts that many
bytes and returns the first `body_len`.

A receiver MUST cap `body_len` (the reference implementation uses 4096)
to bound buffer allocation on hostile input.

Because the salt is random and the remainder is ChaCha20 ciphertext, the
entire message is indistinguishable from random to an observer without
the envelope key. This defeats passive protocol fingerprinting. It does
not provide active-probe resistance.

## 5. Authorization and allocation ordering

On the server, for each connection:

1. Read and process the first handshake message. Failure here (wrong
   envelope key, wrong cipher suite, or an initiator that does not hold
   a valid static key) ends the connection with no client identity
   established and nothing allocated.
2. Take the initiator's static public key from the Noise state and
   authorize it (single-peer: constant comparison to the one configured
   key; multi-client: membership in the configured set). An
   unauthorized key ends the connection.
3. Only now allocate an address (section 6) and build `payload2`.
4. Send the second handshake message.

This ordering guarantees that an unauthenticated or unauthorized peer
can never drive an address allocation.

## 6. Address slots and assignment

An **address slot** is 17 bytes: a 1-byte family tag followed by 16
bytes of address.

```
family = 0  -> unspecified; the 16 bytes are zero
family = 4  -> IPv4 in the first 4 bytes, remainder zero
family = 6  -> IPv6 in all 16 bytes
```

A client MAY request specific addresses via `req_v4` / `req_v6`. The
server returns assignments in `asg_v4` / `asg_v6` with a `prefix` length;
`prefix = 0` means that family was not assigned and the client uses its
locally configured address. Assignment is sticky by session id across
reconnects until the session is reaped after an idle period. IPv6
host addresses are derived from the session id so the spread inside the
prefix is uniform.

Single-peer servers leave both prefixes zero; the client uses its own
configured addresses.

## 7. Transport framing

After the handshake, each lane carries a stream of frames:

```
type(1)              # 0 = single inner unit, 1 = batch
length(2)            # length of the payload that follows
payload(length)      # AEAD ciphertext (keyed mode) or plaintext (open mode)
```

The payload is sealed with the lane's send key (section 3) using
packethose's framed AEAD: a per-lane, per-direction 64-bit counter
nonce that increments per frame and is never transmitted (reliable
in-order TCP keeps the two ends' counters in lockstep). Associated data
is empty; the tag is 16 bytes. In open mode the payload is the plaintext
with no tag.

A **single** frame (`type = 0`) carries one inner unit: one L3 packet,
or — in virtio-net-header mode — a 10-byte little-endian `virtio_net_hdr`
followed by an L3 super-packet carrying GSO metadata. Both ends must
agree on virtio-net-header mode out of band.

A **batch** frame (`type = 1`) carries several inner units concatenated,
each prefixed by its own 16-bit length:

```
sub_len(2) || inner_unit   (repeated until the decrypted payload is consumed)
```

The receiver decrypts once and splits, writing each inner unit to the
TUN. Batching amortizes the per-packet AEAD and socket-write cost across
many datagrams (section 9). A sender emits a single frame for a lone
packet and a batch frame only when several packets are already queued,
so latency-sensitive sparse traffic is never delayed to fill a batch.

A decryption failure, a length of zero (skipped), or any I/O error ends
the lane. A lane that ends is re-established by the client with
exponential backoff; the session and its address survive lane churn.

## 8. Liveness

Each lane sets TCP keepalive (idle 15s, interval 5s, count 3) so a dead
path becomes an error in about 30 seconds. The client re-dials with
exponential backoff (250 ms doubling to 30 s, jittered). The server
reaps a session after roughly 90 seconds with no active lane, releasing
its address.

## 9. UDP throughput acceleration (batching and USO)

Small-datagram UDP is packet-rate-bound: each datagram crosses the TUN
and the AEAD individually, whereas TCP is coalesced into large GSO
super-packets by the kernel. Two mechanisms narrow that gap; both are
Linux kernel-TUN features and degrade gracefully on backends that lack
them (userspace netstack, the multi-client shared TUN).

**Batching.** When the sender finds several datagrams already queued on
the TUN, it packs them into one batch frame (section 7): one AEAD seal
and one socket write for the whole burst, split back out by the
receiver. It is pure userspace, needs no kernel support, and works on
any Linux kernel. It is opportunistic — a lone packet is sent
immediately as a single frame — so it never delays sparse, interactive
traffic to fill a batch.

**UDP segmentation offload (USO).** When both peers' kernels support it
(Linux >= ~6.2), the TUN is opened with TUN_F_USO4/USO6 alongside the
always-on TCP offloads, so the kernel coalesces same-flow UDP into GSO
super-packets on read and re-segments on write, as it does for TCP. USO
is negotiated by the `flags` bit in both handshake payloads (section
3.1) and used only when both sides advertise it; otherwise the lane runs
TCP-offload-only. USO and batching are independent.

Both accelerate inner UDP carried over the tunnel; the wire stays TCP. A
single inner UDP flow is handled by one lane (one core); independent
flows spread across lanes and cores.

## 10. Security properties and non-goals

Provided:

* **Mutual authentication** by static X25519 keys (Noise IK).
* **Forward secrecy**: transport keys derive from the ephemeral DH, and
  the ephemeral private keys are discarded after the handshake, so a
  later compromise of a static key does not decrypt recorded sessions.
* **Confidentiality and integrity** of inner traffic via the negotiated
  AEAD.
* **Passive unobservability** of the handshake via the envelope: no
  constant marker, no fixed length.
* **Pre-authorization allocation safety**: see section 5.

Not provided:

* **Active-probe resistance / traffic mimicry.** The envelope makes the
  stream look random, not like TLS or any specific protocol. An
  adversary that actively probes the endpoint, or that holds the
  server's public key, can identify or de-obfuscate it. For hostile
  networks, run the lanes through a separate censorship-resistant
  transport.
* **Traffic-analysis resistance.** Multi-lane volume and timing are not
  hidden.
* **Replay hardening beyond stickiness.** A captured first message can
  be replayed, but it maps to the original client's sticky address and
  yields no usable session (the replayer lacks the ephemeral private
  key), so it is not an amplification or exhaustion vector.
