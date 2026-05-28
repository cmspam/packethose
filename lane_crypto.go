package packethose

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/flynn/noise"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// laneKeys holds the per-direction transport key material produced by the
// handshake. The data path builds a frameAEAD from each key. encrypted is
// false only in the keyless open-tunnel mode, where the data path runs in
// plaintext.
type laneKeys struct {
	encrypted bool
	kind      Cipher
	tx        []byte // local -> peer
	rx        []byte // peer -> local
}

// aeadOverhead is the AEAD tag length for both supported suites.
const aeadOverhead = 16

func (c Cipher) keyLen() int {
	switch c {
	case CipherAESGCM:
		return 16 // AES-128-GCM: the fast path on AES-NI hardware
	case CipherAES256GCM:
		return 32
	case CipherChaCha:
		return 32
	}
	return 0
}

func (c Cipher) newAEAD(key []byte) (cipher.AEAD, error) {
	switch c {
	case CipherAESGCM, CipherAES256GCM:
		// aes.NewCipher selects AES-128 or AES-256 by key length.
		blk, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(blk)
	case CipherChaCha:
		return chacha20poly1305.New(key)
	}
	return nil, errors.New("no cipher")
}

// frameAEAD seals/opens with a 64-bit counter nonce that increments per
// frame. Reliable in-order TCP keeps the two endpoints in lockstep so the
// counter never appears on the wire. One instance per direction per lane;
// NOT thread-safe. This is the original hand-tuned data-path cipher: no
// per-frame allocation, AES-128-GCM where selected.
type frameAEAD struct {
	aead    cipher.AEAD
	counter uint64
	nonce   [12]byte
}

func newFrameAEAD(c Cipher, key []byte) (*frameAEAD, error) {
	a, err := c.newAEAD(key)
	if err != nil {
		return nil, err
	}
	return &frameAEAD{aead: a}, nil
}

func (f *frameAEAD) seal(dst, plaintext []byte) []byte {
	binary.LittleEndian.PutUint64(f.nonce[:8], f.counter)
	f.counter++
	return f.aead.Seal(dst, f.nonce[:], plaintext, nil)
}

func (f *frameAEAD) open(dst, ciphertext []byte) ([]byte, error) {
	binary.LittleEndian.PutUint64(f.nonce[:8], f.counter)
	f.counter++
	return f.aead.Open(dst, f.nonce[:], ciphertext, nil)
}

func (f *frameAEAD) overhead() int { return f.aead.Overhead() }

// transportKey derives a data-path key of the selected cipher's length
// from a Noise transport cipher state. The Noise handshake authenticates
// the exchange and provides forward secrecy; this lets the hot loop use
// packethose's own AEAD framing (AES-128-GCM where selected) instead of
// Noise's AES-256-GCM transport. Both peers feed the matching direction's
// state, whose key is identical on each side, so the derived keys agree.
func transportKey(c Cipher, cs *noise.CipherState) []byte {
	k := cs.UnsafeKey()
	r := hkdf.Expand(sha256.New, k[:], []byte("packethose-transport-v7"))
	out := make([]byte, c.keyLen())
	_, _ = io.ReadFull(r, out)
	return out
}

// noiseSuite maps a Cipher selection to the Noise cipher suite used for the
// handshake. DH and hash are fixed at X25519 and SHA-256. The suite is not
// negotiated in band: both peers must be configured the same, as in
// WireGuard.
func noiseSuite(c Cipher) noise.CipherSuite {
	if c == CipherChaCha {
		return noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	}
	return noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
}

// noiseProtoName is the canonical Noise protocol name for the negotiated
// cipher, used in the spec and diagnostics.
func noiseProtoName(c Cipher) string {
	if c == CipherChaCha {
		return "Noise_IK_25519_ChaChaPoly_SHA256"
	}
	return "Noise_IK_25519_AESGCM_SHA256"
}

// GenerateKeypair returns a fresh X25519 static keypair (private, public).
func GenerateKeypair() (priv, pub []byte, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return k.Bytes(), k.PublicKey().Bytes(), nil
}

// PublicFromPrivate derives the X25519 public key from a 32-byte private key.
func PublicFromPrivate(priv []byte) ([]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}
	return k.PublicKey().Bytes(), nil
}

func noiseStatic(priv []byte) (noise.DHKey, error) {
	pub, err := PublicFromPrivate(priv)
	if err != nil {
		return noise.DHKey{}, err
	}
	return noise.DHKey{Private: priv, Public: pub}, nil
}

// deriveClientID maps a 32-byte client static public key to the 16-byte
// session identifier used by the multi-client pool and session table.
func deriveClientID(pub []byte) [clientIDLen]byte {
	sum := sha256.Sum256(pub)
	var id [clientIDLen]byte
	copy(id[:], sum[:clientIDLen])
	return id
}
