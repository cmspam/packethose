package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type cipherKind byte

const (
	cipherNone   cipherKind = 0
	cipherAESGCM cipherKind = 1
	cipherChaCha cipherKind = 2
)

func (c cipherKind) String() string {
	switch c {
	case cipherNone:
		return "none"
	case cipherAESGCM:
		return "aes-gcm"
	case cipherChaCha:
		return "chacha20"
	}
	return fmt.Sprintf("unknown(%d)", byte(c))
}

func parseCipher(s string) (cipherKind, error) {
	switch s {
	case "", "none":
		return cipherNone, nil
	case "aes-gcm", "aes":
		return cipherAESGCM, nil
	case "chacha20", "chacha20-poly1305":
		return cipherChaCha, nil
	}
	return cipherNone, fmt.Errorf("unknown cipher %q (want none|aes-gcm|chacha20)", s)
}

func (c cipherKind) keyLen() int {
	switch c {
	case cipherAESGCM:
		return 16
	case cipherChaCha:
		return 32
	}
	return 0
}

func (c cipherKind) newAEAD(key []byte) (cipher.AEAD, error) {
	switch c {
	case cipherAESGCM:
		blk, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(blk)
	case cipherChaCha:
		return chacha20poly1305.New(key)
	}
	return nil, errors.New("no cipher")
}

type laneKeys struct {
	kind cipherKind
	tx   []byte
	rx   []byte
}

// deriveSessionKeys runs HKDF-SHA256 with salt = nonceC || nonceS to produce
// two distinct keys (one per direction). asServer swaps which is local-tx so
// both peers agree on the wire direction.
func deriveSessionKeys(psk, nonceC, nonceS []byte, c cipherKind, asServer bool) (tx, rx []byte, err error) {
	kl := c.keyLen()
	if kl == 0 {
		return nil, nil, nil
	}
	salt := make([]byte, 0, len(nonceC)+len(nonceS))
	salt = append(salt, nonceC...)
	salt = append(salt, nonceS...)
	prk := hkdf.Extract(sha256.New, psk, salt)
	c2s := make([]byte, kl)
	s2c := make([]byte, kl)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk, []byte("packethose c2s "+c.String())), c2s); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk, []byte("packethose s2c "+c.String())), s2c); err != nil {
		return nil, nil, err
	}
	if asServer {
		return s2c, c2s, nil
	}
	return c2s, s2c, nil
}

// frameAEAD seals/opens with a 64-bit counter nonce that increments per frame.
// TCP keeps the two endpoints in lockstep so the counter is not on the wire.
// One instance per direction per lane; NOT thread-safe.
type frameAEAD struct {
	aead    cipher.AEAD
	counter uint64
	nonce   [12]byte
}

func newFrameAEAD(c cipherKind, key []byte) (*frameAEAD, error) {
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
