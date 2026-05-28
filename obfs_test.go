package packethose

import (
	"bytes"
	"testing"
)

func TestObfsRoundtrip(t *testing.T) {
	key := bytesPattern(32)
	body := bytesPattern(131)
	for i := 0; i < 50; i++ {
		var buf bytes.Buffer
		if err := writeObfMsg(&buf, key, body); err != nil {
			t.Fatalf("write: %v", err)
		}
		got, err := readObfMsg(&buf, key)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if !bytes.Equal(got, body) {
			t.Fatalf("roundtrip mismatch")
		}
	}
}

// TestObfsNoConstantPrefix verifies the wire bytes carry no fixed marker:
// the prefix differs across messages with identical bodies.
func TestObfsNoConstantPrefix(t *testing.T) {
	key := bytesPattern(32)
	body := bytesPattern(131)
	var first []byte
	allSame := true
	for i := 0; i < 8; i++ {
		var buf bytes.Buffer
		if err := writeObfMsg(&buf, key, body); err != nil {
			t.Fatalf("write: %v", err)
		}
		head := append([]byte(nil), buf.Bytes()[:8]...)
		if first == nil {
			first = head
		} else if !bytes.Equal(head, first) {
			allSame = false
		}
	}
	if allSame {
		t.Fatal("message prefix is constant across runs; obfuscation not randomizing")
	}
}

// TestObfsWrongKey: a reader with the wrong key must not recover the body.
func TestObfsWrongKey(t *testing.T) {
	key := bytesPattern(32)
	wrong := bytes.Repeat([]byte{0x5a}, 32)
	body := bytesPattern(131)
	for i := 0; i < 50; i++ {
		var buf bytes.Buffer
		if err := writeObfMsg(&buf, key, body); err != nil {
			t.Fatalf("write: %v", err)
		}
		got, err := readObfMsg(&buf, wrong)
		if err == nil && bytes.Equal(got, body) {
			t.Fatal("wrong key recovered the body")
		}
	}
}

// TestObfsKeyFromServerPub is deterministic for a given server key.
func TestObfsKeyFromServerPub(t *testing.T) {
	_, pub := genKeyT(t)
	k1 := obfsKeyFromServerPub(pub)
	k2 := obfsKeyFromServerPub(pub)
	if !bytes.Equal(k1, k2) || len(k1) != 32 {
		t.Fatal("obfs key derivation is not deterministic / wrong length")
	}
	_, other := genKeyT(t)
	if bytes.Equal(k1, obfsKeyFromServerPub(other)) {
		t.Fatal("different server keys produced the same obfs key")
	}
}

// FuzzReadObfMsg feeds arbitrary bytes to the envelope decoder to ensure
// it never panics or over-reads on hostile input.
func FuzzReadObfMsg(f *testing.F) {
	key := bytesPattern(32)
	var seed bytes.Buffer
	_ = writeObfMsg(&seed, key, bytesPattern(131))
	f.Add(seed.Bytes())
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xff}, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = readObfMsg(bytes.NewReader(data), key)
	})
}
