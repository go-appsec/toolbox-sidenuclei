package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-appsec/toolbox/sidecar"
)

// handler embeds BaseHandler and wires OnShutdown to cancel the pull loop context.
type handler struct {
	sidecar.BaseHandler
	cancel context.CancelFunc
}

func (h *handler) OnShutdown(drainSeconds int) {
	h.cancel()
}

func main() {
	cfg := parseFlags()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg); err != nil {
		fmt.Fprintln(os.Stderr, "sidenuclei:", err)
		os.Exit(1)
	}
}

func run(parent context.Context, cfg Config) error {
	conn, err := connect(parent, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.Log("info", "attached", map[string]any{"instance_id": cfg.InstanceID})
	_ = conn.ReportMetrics(map[string]int64{
		"flows_observed":    0,
		"endpoints_scanned": 0,
		"findings":          0,
	}, nil)

	// OnShutdown cancels ctx to drain the pull loop; Serve stays on parent so a
	// sectool shutdown returns via the remote close (nil), not ctx cancellation.
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	h := &handler{cancel: cancel}

	go pullLoop(ctx, conn, cfg)

	err = conn.Serve(parent, h)
	if err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// pullLoop is the phase-1 stub: it just ticks and honors ctx.Done().
func pullLoop(ctx context.Context, conn *sidecar.Conn, cfg Config) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// phase-2: proxy_poll cursor loop goes here
		}
	}
}
