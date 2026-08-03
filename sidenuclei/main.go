package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/go-appsec/toolbox-sidenuclei/sidenuclei/nuclei"
	"github.com/go-appsec/toolbox/sidecar"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// handler embeds BaseHandler and wires OnShutdown to cancel the pull loop context.
// It holds the shared scanner so OnInvokeTool can serve live status.
type handler struct {
	sidecar.BaseHandler
	cancel context.CancelFunc
	s      *scanner
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
	if err := cfg.parse(); err != nil {
		return err
	}

	engine, err := nuclei.New(parent, cfg.engineConfig())
	if err != nil {
		return err
	}
	defer func() { _ = engine.Close() }()

	conn, err := connect(parent, cfg)
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

	// child ctx drains the pull loop on shutdown; Serve stays on parent
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	// scanner is shared between the pull loop and the status tool handler
	invoke := func(ctx context.Context, tool string, params any) (wire.CoreInvokeResult, error) {
		return conn.CoreInvoke(ctx, tool, params)
	}
	s := newScanner(cfg, invoke, engine)
	s.logf = func(level, message string, fields map[string]any) {
		_ = conn.Log(level, message, fields)
	}
	h := &handler{cancel: cancel, s: s}

	go pullLoop(ctx, conn, s)

	err = conn.Serve(parent, h)
	if err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
