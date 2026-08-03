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
	h := &handler{cancel: cancel}

	go pullLoop(ctx, conn, cfg, engine)

	err = conn.Serve(parent, h)
	if err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
