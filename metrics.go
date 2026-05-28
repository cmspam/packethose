package packethose

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"sync/atomic"
	"time"
)

// Metrics holds the server's control-plane counters. All increments are
// off the data path: connection accepts, handshake outcomes, rate-limit
// drops, and session lifecycle. Per-client byte totals come from the
// kernel via StatProvider, not from counting in userspace. A nil
// *Metrics is safe and ignores every call, so callers need no guards.
type Metrics struct {
	accepts     atomic.Int64
	hsOK        atomic.Int64
	hsFail      atomic.Int64
	rateLimited atomic.Int64
	slotsFull   atomic.Int64
	sessOpened  atomic.Int64
	sessClosed  atomic.Int64

	// statProvider, when set, supplies per-client byte counters for the
	// exposition. It is read lazily on scrape.
	statProvider func() []ByteStat
}

// ByteStat is one client's kernel-side byte totals for exposition.
type ByteStat struct {
	Addr    string
	TxBytes uint64
	RxBytes uint64
}

// NewMetrics returns an initialized Metrics.
func NewMetrics() *Metrics { return &Metrics{} }

// SetStatProvider registers the source of per-client byte counters.
func (m *Metrics) SetStatProvider(fn func() []ByteStat) {
	if m == nil {
		return
	}
	m.statProvider = fn
}

func (m *Metrics) incAccept() {
	if m != nil {
		m.accepts.Add(1)
	}
}
func (m *Metrics) incHandshakeOK() {
	if m != nil {
		m.hsOK.Add(1)
	}
}
func (m *Metrics) incHandshakeFail() {
	if m != nil {
		m.hsFail.Add(1)
	}
}
func (m *Metrics) incRateLimited() {
	if m != nil {
		m.rateLimited.Add(1)
	}
}
func (m *Metrics) incSlotsFull() {
	if m != nil {
		m.slotsFull.Add(1)
	}
}
func (m *Metrics) incSessionOpened() {
	if m != nil {
		m.sessOpened.Add(1)
	}
}
func (m *Metrics) incSessionClosed() {
	if m != nil {
		m.sessClosed.Add(1)
	}
}

// WritePrometheus renders the metrics in Prometheus text exposition
// format.
func (m *Metrics) WritePrometheus(w io.Writer) {
	if m == nil {
		return
	}
	fmt.Fprintf(w, "# HELP packethose_accepts_total Connections accepted before any gating.\n")
	fmt.Fprintf(w, "# TYPE packethose_accepts_total counter\n")
	fmt.Fprintf(w, "packethose_accepts_total %d\n", m.accepts.Load())

	fmt.Fprintf(w, "# HELP packethose_handshakes_total Handshake outcomes by result.\n")
	fmt.Fprintf(w, "# TYPE packethose_handshakes_total counter\n")
	fmt.Fprintf(w, "packethose_handshakes_total{result=\"ok\"} %d\n", m.hsOK.Load())
	fmt.Fprintf(w, "packethose_handshakes_total{result=\"fail\"} %d\n", m.hsFail.Load())

	fmt.Fprintf(w, "# HELP packethose_rate_limited_total Connections dropped by the per-IP rate limiter.\n")
	fmt.Fprintf(w, "# TYPE packethose_rate_limited_total counter\n")
	fmt.Fprintf(w, "packethose_rate_limited_total %d\n", m.rateLimited.Load())

	fmt.Fprintf(w, "# HELP packethose_handshake_slots_exhausted_total Connections dropped because the in-flight handshake cap was reached.\n")
	fmt.Fprintf(w, "# TYPE packethose_handshake_slots_exhausted_total counter\n")
	fmt.Fprintf(w, "packethose_handshake_slots_exhausted_total %d\n", m.slotsFull.Load())

	fmt.Fprintf(w, "# HELP packethose_sessions_active Current multi-client sessions.\n")
	fmt.Fprintf(w, "# TYPE packethose_sessions_active gauge\n")
	fmt.Fprintf(w, "packethose_sessions_active %d\n", m.sessOpened.Load()-m.sessClosed.Load())

	if m.statProvider != nil {
		stats := m.statProvider()
		sort.Slice(stats, func(i, j int) bool { return stats[i].Addr < stats[j].Addr })
		fmt.Fprintf(w, "# HELP packethose_client_tx_bytes Bytes from a client toward the internet (kernel counter).\n")
		fmt.Fprintf(w, "# TYPE packethose_client_tx_bytes counter\n")
		for _, s := range stats {
			fmt.Fprintf(w, "packethose_client_tx_bytes{addr=%q} %d\n", s.Addr, s.TxBytes)
		}
		fmt.Fprintf(w, "# HELP packethose_client_rx_bytes Bytes toward a client from the internet (kernel counter).\n")
		fmt.Fprintf(w, "# TYPE packethose_client_rx_bytes counter\n")
		for _, s := range stats {
			fmt.Fprintf(w, "packethose_client_rx_bytes{addr=%q} %d\n", s.Addr, s.RxBytes)
		}
	}
}

// serveMetrics runs an HTTP server exposing /metrics and /healthz until
// ctx is canceled. Errors other than the clean shutdown are logged.
func serveMetrics(ctx context.Context, addr string, m *Metrics, logger *log.Logger) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		m.WritePrometheus(w)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Printf("metrics: listen %s: %v", addr, err)
		return
	}
	logger.Printf("metrics: serving on %s (/metrics, /healthz)", addr)
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		logger.Printf("metrics: serve: %v", err)
	}
}
