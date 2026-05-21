package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	hsMagic   uint32 = 0x50484F53 // "PHOS"
	hsVersion byte   = 2
	hsTimeout        = 5 * time.Second
	nonceLen         = 32
	macLen           = 32
)

// initiateHandshake (client). With psk==nil and want==cipherNone, no handshake
// runs. Otherwise:
//
//   client -> magic(4) ver(1)=2 cipher(1) nonce_c(32)
//   server -> magic(4) ver(1)=2 cipher(1) HMAC(psk, ver||cipher||nonce_c)(32) nonce_s(32)
//   client -> HMAC(psk, ver||cipher||nonce_s)(32)
//
// Keys (if cipher != none) are derived from HKDF over (psk, nonce_c||nonce_s).
func initiateHandshake(c net.Conn, psk []byte, want cipherKind) (laneKeys, error) {
	if len(psk) == 0 {
		if want != cipherNone {
			return laneKeys{}, fmt.Errorf("--encrypt requires --psk")
		}
		return laneKeys{}, nil
	}
	c.SetDeadline(time.Now().Add(hsTimeout))
	defer c.SetDeadline(time.Time{})

	var nonceC [nonceLen]byte
	if _, err := rand.Read(nonceC[:]); err != nil {
		return laneKeys{}, err
	}
	hdr := make([]byte, 4+1+1+nonceLen)
	binary.BigEndian.PutUint32(hdr[0:4], hsMagic)
	hdr[4] = hsVersion
	hdr[5] = byte(want)
	copy(hdr[6:], nonceC[:])
	if _, err := c.Write(hdr); err != nil {
		return laneKeys{}, err
	}

	resp := make([]byte, 4+1+1+macLen+nonceLen)
	if _, err := io.ReadFull(c, resp); err != nil {
		return laneKeys{}, err
	}
	if binary.BigEndian.Uint32(resp[0:4]) != hsMagic {
		return laneKeys{}, fmt.Errorf("handshake: bad magic")
	}
	if resp[4] != hsVersion {
		return laneKeys{}, fmt.Errorf("handshake: version mismatch (got %d, want %d)", resp[4], hsVersion)
	}
	got := cipherKind(resp[5])
	if got != want {
		return laneKeys{}, fmt.Errorf("handshake: cipher rejected (sent %s, got %s)", want, got)
	}
	authIn := append([]byte{hsVersion, byte(got)}, nonceC[:]...)
	if !hmac.Equal(hmacSHA256(psk, authIn), resp[6:6+macLen]) {
		return laneKeys{}, fmt.Errorf("handshake: server HMAC mismatch")
	}
	nonceS := resp[6+macLen:]

	cliAuth := append([]byte{hsVersion, byte(got)}, nonceS...)
	if _, err := c.Write(hmacSHA256(psk, cliAuth)); err != nil {
		return laneKeys{}, err
	}

	tx, rx, err := deriveSessionKeys(psk, nonceC[:], nonceS, got, false)
	if err != nil {
		return laneKeys{}, err
	}
	return laneKeys{kind: got, tx: tx, rx: rx}, nil
}

// acceptHandshake (server). Mirror of initiateHandshake; accepts whatever
// cipher the client requested.
func acceptHandshake(c net.Conn, psk []byte) (laneKeys, error) {
	if len(psk) == 0 {
		return laneKeys{}, nil
	}
	c.SetDeadline(time.Now().Add(hsTimeout))
	defer c.SetDeadline(time.Time{})

	hdr := make([]byte, 4+1+1+nonceLen)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return laneKeys{}, err
	}
	if binary.BigEndian.Uint32(hdr[0:4]) != hsMagic {
		return laneKeys{}, fmt.Errorf("handshake: bad magic")
	}
	if hdr[4] != hsVersion {
		return laneKeys{}, fmt.Errorf("handshake: version mismatch (got %d, want %d)", hdr[4], hsVersion)
	}
	got := cipherKind(hdr[5])
	if got != cipherNone && got != cipherAESGCM && got != cipherChaCha {
		return laneKeys{}, fmt.Errorf("handshake: unknown cipher %d", got)
	}
	nonceC := hdr[6:]

	var nonceS [nonceLen]byte
	if _, err := rand.Read(nonceS[:]); err != nil {
		return laneKeys{}, err
	}

	resp := make([]byte, 4+1+1+macLen+nonceLen)
	binary.BigEndian.PutUint32(resp[0:4], hsMagic)
	resp[4] = hsVersion
	resp[5] = byte(got)
	authIn := append([]byte{hsVersion, byte(got)}, nonceC...)
	copy(resp[6:6+macLen], hmacSHA256(psk, authIn))
	copy(resp[6+macLen:], nonceS[:])
	if _, err := c.Write(resp); err != nil {
		return laneKeys{}, err
	}

	ack := make([]byte, macLen)
	if _, err := io.ReadFull(c, ack); err != nil {
		return laneKeys{}, err
	}
	cliAuth := append([]byte{hsVersion, byte(got)}, nonceS[:]...)
	if !bytes.Equal(hmacSHA256(psk, cliAuth), ack) {
		return laneKeys{}, fmt.Errorf("handshake: client HMAC mismatch")
	}

	tx, rx, err := deriveSessionKeys(psk, nonceC, nonceS[:], got, true)
	if err != nil {
		return laneKeys{}, err
	}
	return laneKeys{kind: got, tx: tx, rx: rx}, nil
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
