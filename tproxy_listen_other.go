//go:build !linux

package packethose

import (
	"context"
	"errors"
	"log"
)

// TPROXYListener is a no-op stub on non-Linux builds. TPROXY relies
// on Linux-specific socket options (IP_TRANSPARENT, IP_RECVORIGDSTADDR).
type TPROXYListener struct {
	cfg    TPROXYConfig
	logger *log.Logger
}

func NewTPROXYListener(cfg TPROXYConfig, logger *log.Logger) (*TPROXYListener, error) {
	if cfg.Enabled {
		return nil, errors.New("tproxy: linux-only")
	}
	return &TPROXYListener{cfg: cfg, logger: logger}, nil
}

func (t *TPROXYListener) Start(ctx context.Context) error { return nil }
func (t *TPROXYListener) Stop()                            {}
