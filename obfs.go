package packethose

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
)

// Handshake obfuscation (Tier-1).
//
// Without obfuscation a packethose connection would open with the raw
// Noise handshake: a cleartext ephemeral public key followed by fixed
// structure, which a passive middlebox can fingerprint. The envelope
// below removes those tells: every handshake message is wrapped in a
// ChaCha20 keystream keyed by HKDF(endpoint-key, random-salt), with the
// salt sent in clear and random trailing padding inside the encrypted
// region. To an observer without the endpoint key the salt is random
// and the ciphertext is indistinguishable from random, so there is no
// constant byte and no fixed length to match on.
//
// The endpoint key is the server's static public key (see
// obfsKeyFromServerPub): the client knows it as the Noise IK pre-known
// responder key, and the server knows its own. This layer is
// confidentiality-for-camouflage only, never the security boundary. The
// data path is never enveloped, so throughput is unaffected.

const (
	obfsSaltLen = 16
	obfsMaxPad  = 255
	// obfsMaxBody caps a decoded message so a hostile peer cannot make
	// the server allocate an unbounded buffer off a forged length.
	obfsMaxBody = 4096
	obfsInfo    = "packethose-obfs-v7"
)

// obfsKeyFromServerPub derives the envelope key from the server's static
// public key. Camouflage only: an adversary already holding the server's
// public key can de-obfuscate, but a passive middlebox cannot.
func obfsKeyFromServerPub(serverPub []byte) []byte {
	r := hkdf.New(sha256.New, serverPub, nil, []byte(obfsInfo+"-key"))
	out := make([]byte, 32)
	_, _ = io.ReadFull(r, out)
	return out
}

func obfsCipher(key, salt []byte) (*chacha20.Cipher, error) {
	r := hkdf.New(sha256.New, key, salt, []byte(obfsInfo))
	var kn [chacha20.KeySize + chacha20.NonceSize]byte
	if _, err := io.ReadFull(r, kn[:]); err != nil {
		return nil, err
	}
	return chacha20.NewUnauthenticatedCipher(kn[:chacha20.KeySize], kn[chacha20.KeySize:])
}

// writeObfMsg frames one handshake message as
//
//	salt(16) || ChaCha20( u16 bodyLen || u16 padLen || body || random-pad )
//
// so the only cleartext on the wire is the random salt. Body length is
// carried inside the keystream, so messages can be any size.
func writeObfMsg(c io.Writer, key, body []byte) error {
	if len(body) > obfsMaxBody {
		return fmt.Errorf("obfs: body %d exceeds max %d", len(body), obfsMaxBody)
	}
	var salt [obfsSaltLen]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return err
	}
	ciph, err := obfsCipher(key, salt[:])
	if err != nil {
		return err
	}
	var padByte [1]byte
	if _, err := rand.Read(padByte[:]); err != nil {
		return err
	}
	padLen := int(padByte[0])

	inner := make([]byte, 4+len(body)+padLen)
	binary.BigEndian.PutUint16(inner[0:2], uint16(len(body)))
	binary.BigEndian.PutUint16(inner[2:4], uint16(padLen))
	copy(inner[4:], body)
	if padLen > 0 {
		if _, err := rand.Read(inner[4+len(body):]); err != nil {
			return err
		}
	}
	ciph.XORKeyStream(inner, inner)

	out := make([]byte, 0, obfsSaltLen+len(inner))
	out = append(out, salt[:]...)
	out = append(out, inner...)
	_, err = c.Write(out)
	return err
}

// readObfMsg reads one enveloped message and returns its body, discarding
// the random padding. It enforces obfsMaxBody so a forged length cannot
// drive an unbounded read.
func readObfMsg(c io.Reader, key []byte) ([]byte, error) {
	var salt [obfsSaltLen]byte
	if _, err := io.ReadFull(c, salt[:]); err != nil {
		return nil, err
	}
	ciph, err := obfsCipher(key, salt[:])
	if err != nil {
		return nil, err
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return nil, err
	}
	ciph.XORKeyStream(hdr, hdr)
	bodyLen := int(binary.BigEndian.Uint16(hdr[0:2]))
	padLen := int(binary.BigEndian.Uint16(hdr[2:4]))
	if bodyLen > obfsMaxBody {
		return nil, fmt.Errorf("obfs: framed body length %d exceeds max %d", bodyLen, obfsMaxBody)
	}
	buf := make([]byte, bodyLen+padLen)
	if _, err := io.ReadFull(c, buf); err != nil {
		return nil, err
	}
	ciph.XORKeyStream(buf, buf)
	return buf[:bodyLen], nil
}
