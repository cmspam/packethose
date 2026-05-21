//go:build linux

package packethose

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// tcpBrutalParams is the brutal kernel module's setsockopt level for the
// per-flow rate parameters. From the apernet/tcp-brutal source:
//
//	struct brutal_params {
//	    u64 rate;       // bytes/second
//	    u32 cwnd_gain;  // tenths (10 = 1.0x, 15 = 1.5x)
//	} __packed;          // wire size: 12 bytes
const tcpBrutalParams = 23301

// DefaultBrutalCwndGain is the cwnd_gain used by SetBrutalRate when the
// caller does not specify one. 15 (== 1.5x) matches Hysteria's default.
const DefaultBrutalCwndGain = 15

// SetBrutalRate switches the TCP socket to the tcp-brutal congestion control
// algorithm with the given bytes/second rate. Requires the brutal kernel
// module to be loaded on the host. cwndGain is in tenths (15 = 1.5x); pass 0
// to use DefaultBrutalCwndGain.
//
// Returns an error if the conn is not TCP, the kernel rejects "brutal" as a
// CC algorithm (module not loaded), or the params sockopt fails. On error,
// the connection is left with whatever CC it had before.
func SetBrutalRate(c net.Conn, rate uint64, cwndGain uint32) error {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return errors.New("brutal: not a *net.TCPConn")
	}
	if cwndGain == 0 {
		cwndGain = DefaultBrutalCwndGain
	}
	sc, err := tc.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	ctlErr := sc.Control(func(fd uintptr) {
		if err := unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, "brutal"); err != nil {
			setErr = fmt.Errorf("brutal: set TCP_CONGESTION: %w (module loaded?)", err)
			return
		}
		var buf [12]byte
		binary.LittleEndian.PutUint64(buf[0:8], rate)
		binary.LittleEndian.PutUint32(buf[8:12], cwndGain)
		if err := unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, tcpBrutalParams, string(buf[:])); err != nil {
			setErr = fmt.Errorf("brutal: set TCP_BRUTAL_PARAMS: %w", err)
		}
	})
	if ctlErr != nil {
		return ctlErr
	}
	return setErr
}

// BrutalTuner returns a TuneSocket function that applies tcp-brutal with the
// given rate (bytes/sec). Errors from the kernel are logged via the provided
// log function and do not abort the lane — connections continue with the
// previous CC algorithm if brutal is unavailable.
//
// Wire this into ClientConfig.TuneSocket or ServerConfig.TuneSocket:
//
//	cfg.TuneSocket = packethose.BrutalTuner(125_000_000, 0, log.Printf) // 1 Gbps
func BrutalTuner(rate uint64, cwndGain uint32, logf func(format string, args ...any)) func(net.Conn) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return func(c net.Conn) {
		if err := SetBrutalRate(c, rate, cwndGain); err != nil {
			logf("brutal disabled: %v", err)
		}
	}
}
