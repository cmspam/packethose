//go:build linux

package packethose

import (
	"net/netip"
	"testing"
)

func TestInnerDstV4(t *testing.T) {
	// Minimal IPv4 header: version=4, ihl=5, total=20, src=10.0.0.1, dst=10.66.0.10
	pkt := make([]byte, 20)
	pkt[0] = 0x45
	pkt[16], pkt[17], pkt[18], pkt[19] = 10, 66, 0, 10
	got, ok := innerDst(pkt, false)
	if !ok {
		t.Fatal("parse failed")
	}
	want := netip.MustParseAddr("10.66.0.10")
	if got != want {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestInnerDstV6(t *testing.T) {
	// Minimal IPv6 header: version=6, dst at bytes 24..40
	pkt := make([]byte, 40)
	pkt[0] = 0x60
	dst := netip.MustParseAddr("fd00:66::a")
	dstBytes := dst.As16()
	copy(pkt[24:40], dstBytes[:])
	got, ok := innerDst(pkt, false)
	if !ok {
		t.Fatal("parse failed")
	}
	if got != dst {
		t.Errorf("got %v want %v", got, dst)
	}
}

func TestInnerDstVnetHdrSkipped(t *testing.T) {
	// 10-byte vnet_hdr prefix then a v4 packet
	pkt := make([]byte, virtioNetHdrLen+20)
	pkt[virtioNetHdrLen] = 0x45
	pkt[virtioNetHdrLen+16], pkt[virtioNetHdrLen+17], pkt[virtioNetHdrLen+18], pkt[virtioNetHdrLen+19] = 10, 66, 0, 12
	got, ok := innerDst(pkt, true)
	if !ok {
		t.Fatal("parse failed")
	}
	if got != netip.MustParseAddr("10.66.0.12") {
		t.Errorf("got %v", got)
	}
}

func TestInnerDstRejectsTooShort(t *testing.T) {
	if _, ok := innerDst([]byte{}, false); ok {
		t.Error("empty should fail")
	}
	if _, ok := innerDst([]byte{0x45}, false); ok {
		t.Error("1-byte should fail")
	}
	if _, ok := innerDst(make([]byte, 5), true); ok {
		t.Error("vnet_hdr-only should fail")
	}
}

func TestInnerDstRejectsUnknownVersion(t *testing.T) {
	pkt := make([]byte, 20)
	pkt[0] = 0x55 // version 5
	if _, ok := innerDst(pkt, false); ok {
		t.Error("version 5 should fail")
	}
}
