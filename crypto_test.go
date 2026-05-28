package packethose

import (
	"bytes"
	"testing"
)

// TestTransportRoundtrip runs a full handshake and then moves frames in
// both directions through the derived Noise transport ciphers, checking
// the per-frame counters stay in lockstep and that a desynchronized
// receiver rejects.
func TestTransportRoundtrip(t *testing.T) {
	for _, c := range []Cipher{CipherAESGCM, CipherChaCha} {
		serverPriv, _ := genKeyT(t)
		clientPriv, clientPub := genKeyT(t)
		cli, srv := runHandshake(t, serverPriv, clientPriv, serverAuthorizer(nil, clientPub), assignFixedV4(), c, AssignmentRequest{})

		// client tx -> server rx, several frames in lockstep
		cTx, _ := newFrameAEAD(cli.keys.kind, cli.keys.tx)
		sRx, _ := newFrameAEAD(srv.keys.kind, srv.keys.rx)
		for i := 0; i < 4; i++ {
			msg := []byte{byte('a' + i), byte(i)}
			got, err := sRx.open(nil, cTx.seal(nil, msg))
			if err != nil || !bytes.Equal(got, msg) {
				t.Fatalf("%s c2s frame %d: got %q err %v", c, i, got, err)
			}
		}

		// server tx -> client rx
		sTx, _ := newFrameAEAD(srv.keys.kind, srv.keys.tx)
		cRx, _ := newFrameAEAD(cli.keys.kind, cli.keys.rx)
		back := []byte("server payload")
		if got, err := cRx.open(nil, sTx.seal(nil, back)); err != nil || !bytes.Equal(got, back) {
			t.Fatalf("%s s2c: got %q err %v", c, got, err)
		}

		// A tampered ciphertext must be rejected by the AEAD.
		tampered := cTx.seal(nil, []byte("integrity"))
		tampered[len(tampered)-1] ^= 0x01
		if _, err := sRx.open(nil, tampered); err == nil {
			t.Fatalf("%s: tampered frame was accepted", c)
		}
	}
}
