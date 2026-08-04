package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-appsec/toolbox-sidenuclei/sidenuclei/nuclei"
	"github.com/go-appsec/toolbox/sidecar"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// shutdownCloseGrace bounds how long we wait for the nuclei engines to close and
// drain their OAST sessions before letting sectool's graceful shutdown proceed.
const shutdownCloseGrace = 2 * time.Second

// handler embeds BaseHandler and wires OnShutdown to cancel in-progress work, then
// closes the nuclei engine so OAST sessions drain without blocking shutdown.
type handler struct {
	sidecar.BaseHandler
	cancel context.CancelFunc
	engine scanEngine
	s      *scanner
}

// OnShutdown cancels the poll loop and in-progress scans, then tries to close the
// nuclei engine (draining OAST sessions). Close runs on a background goroutine so a
// slow engine teardown never blocks graceful shutdown beyond shutdownCloseGrace.
func (h *handler) OnShutdown(drainSeconds int) {
	h.cancel() // cancel poll loop + in-progress scans; closeQueue runs in pullLoop's defer

	done := make(chan struct{})
	go func() { _ = h.engine.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(shutdownCloseGrace):
	}
}

func main() {
	cfg := parseFlags()
	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "sidenuclei:", err)
		os.Exit(1)
	}
}

func run(cfg Config) error {
	if err := cfg.parse(); err != nil {
		return err
	}

	engine, err := nuclei.New(context.Background(), cfg.engineConfig())
	if err != nil {
		return err
	}

	conn, err := connect(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.Log("info", "attached", nil)
	if classes := cfg.enabledInjectionClasses(); len(classes) > 0 {
		_ = conn.Log(logWarn, "active injection fuzzing enabled ("+strings.Join(classes, ",")+"): payloads are sent with captured (often authenticated) requests to "+cfg.FuzzMethods+" endpoints; ensure the target scope is authorized", nil)
	}
	_ = conn.ReportMetrics(map[string]int64{
		"flows_observed":    0,
		"endpoints_scanned": 0,
		"findings":          0,
	}, nil)

	// child ctx drains the poll loop on shutdown; workers run on background ctx
	ctx, cancel := context.WithCancel(context.Background())

	// scanner is shared between the pull loop and the status tool handler
	invoke := func(ctx context.Context, tool string, params any) (wire.CoreInvokeResult, error) {
		return conn.CoreInvoke(ctx, tool, params)
	}
	s := newScanner(cfg, invoke, engine)
	s.logf = func(level, message string, fields map[string]any) {
		_ = conn.Log(level, message, fields)
	}
	h := &handler{cancel: cancel, engine: engine, s: s}

	// Deferred cleanup covers local signal/early-error exits; Engine.Close is idempotent vs OnShutdown
	defer func() {
		h.cancel() // stop poll loop + in-progress scans before we return
		_ = engine.Close()
	}()

	go pullLoop(ctx, conn, s)

	// signal context: exits Serve on direct SIGINT/SIGTERM (not via sectool)
	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err = conn.Serve(sigCtx, h)
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
