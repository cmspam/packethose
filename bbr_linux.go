//go:build linux

package packethose

import (
	"net"
	"os"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// bbrAvailable reports whether the kernel lists "bbr" as an allowed
// congestion control algorithm. The check runs once at first call.
var bbrAvailable = sync.OnceValue(func() bool {
	data, err := os.ReadFile("/proc/sys/net/ipv4/tcp_allowed_congestion_control")
	if err != nil {
		return false
	}
	for _, f := range strings.Fields(string(data)) {
		if f == "bbr" {
			return true
		}
	}
	return false
})

// BBRAvailable reports whether the kernel exposes BBR as an allowed
// congestion control algorithm on this host.
func BBRAvailable() bool { return bbrAvailable() }

// applyBBR sets TCP_CONGESTION="bbr" on the underlying TCP socket. It
// is a no-op for non-TCP conns or when BBR is not in the kernel's
// allowed list. Returns the kernel error if the setsockopt itself
// fails so callers can decide whether to log.
func applyBBR(c net.Conn) error {
	if !bbrAvailable() {
		return nil
	}
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return nil
	}
	sc, err := tc.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	cerr := sc.Control(func(fd uintptr) {
		setErr = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, "bbr")
	})
	if cerr != nil {
		return cerr
	}
	return setErr
}

// BBRTuner returns a TuneSocket function that installs BBR per socket.
// Errors are silently ignored: BBR is best-effort, the existing CC
// remains if the kernel refuses.
func BBRTuner() func(net.Conn) {
	return func(c net.Conn) { _ = applyBBR(c) }
}
