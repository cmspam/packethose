package packethose

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// fakeConn adapts an io.Reader to net.Conn for decode fuzzing: reads
// come from the reader, writes are discarded, deadlines are no-ops.
type fakeConn struct{ r io.Reader }

func (c fakeConn) Read(b []byte) (int, error)       { return c.r.Read(b) }
func (c fakeConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c fakeConn) Close() error                     { return nil }
func (c fakeConn) LocalAddr() net.Addr              { return fakeAddr{} }
func (c fakeConn) RemoteAddr() net.Addr             { return fakeAddr{} }
func (c fakeConn) SetDeadline(time.Time) error      { return nil }
func (c fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c fakeConn) SetWriteDeadline(time.Time) error { return nil }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "fake" }
func (fakeAddr) String() string  { return "fake" }

// FuzzAcceptHandshake feeds arbitrary bytes to the server-side Noise
// handshake under a fixed server key. It must always return a value or
// error, never panic, regardless of input.
func FuzzAcceptHandshake(f *testing.F) {
	serverStatic, err := noiseStatic(bytesPattern(32))
	if err != nil {
		f.Fatalf("server static: %v", err)
	}
	obfsKey := obfsKeyFromServerPub(serverStatic.Public)
	authorize := serverAuthorizer(nil, bytesPattern(32))

	var seed bytes.Buffer
	_ = writeObfMsg(&seed, obfsKey, bytesPattern(120))
	f.Add(seed.Bytes())
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0x00}, 200))

	f.Fuzz(func(t *testing.T, data []byte) {
		c := fakeConn{r: bytes.NewReader(data)}
		_, _ = acceptHandshake(c, serverStatic, CipherAESGCM, false, authorize, nil)
	})
}
