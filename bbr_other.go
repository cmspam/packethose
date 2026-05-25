//go:build !linux

package packethose

import "net"

func BBRAvailable() bool          { return false }
func applyBBR(_ net.Conn) error   { return nil }
func BBRTuner() func(net.Conn)    { return func(net.Conn) {} }
