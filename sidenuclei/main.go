package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-appsec/toolbox-sidenuclei/sidenuclei/nuclei"
	"github.com/go-appsec/toolbox/sidecar"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// Reconnect pacing. Vars so tests can shorten them.
var (
	reconnectInitial = time.Second
	reconnectMax     = 30 * time.Second
	// reconnectStable is the served duration after which a session counts as healthy,
	// resetting the backoff escalation and the outage window.
	reconnectStable = 10 * time.Second
	// reconnectWindow bounds how long the process keeps retrying a dead host before
	// exiting nonzero so a supervisor can intervene.
	reconnectWindow = 5 * time.Minute
)

// handler embeds BaseHandler; OnShutdown cancels the session so a sectool drain is
// not slowed by polling or in-flight scans. The conn drops when the host finishes
// shutting down and serveForever reconnects. The scanner holds no sectool-persisted
// state, so no OnClose cleanup RPCs are owed.
type handler struct {
	sidecar.BaseHandler
	cancel context.CancelFunc // cancels the session ctx
	s      *scanner
}

// OnShutdown cancels this session's poll loop and in-progress scans.
func (h *handler) OnShutdown(int) { h.cancel() }

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

	// engines are process-global: warm across reconnects, drained once at exit
	engine, err := nuclei.New(context.Background(), cfg.engineConfig())
	if err != nil {
		return err
	}
	defer func() { _ = engine.Close() }()

	// one scanner outlives every session: dedup state and counters survive reconnects
	s := newScanner(cfg, nil, engine)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return serveForever(ctx, cfg, s)
}

// serveForever dials sectool and scans until the signal context fires, reconnecting
// with backoff when the transport drops. A failed first dial is fatal (bad socket,
// host never up). Retries continue until reconnectWindow elapses without a healthy
// session, then the returned error makes the process exit nonzero so a supervisor
// can intervene.
func serveForever(ctx context.Context, cfg Config, s *scanner) error {
	backoff := reconnectInitial
	var outage time.Time // start of the current outage window; zero while healthy

	// reconnectWait paces one failed attempt. retry=false means stop: fatal is nil
	// for a signal exit, set once the outage window has elapsed.
	reconnectWait := func(cause error) (retry bool, fatal error) {
		if outage.IsZero() {
			outage = time.Now()
		}
		if time.Since(outage) > reconnectWindow {
			return false, fmt.Errorf("no healthy sectool session for over %s: %w", reconnectWindow, cause)
		}
		log.Printf("sidenuclei: reconnect: %v (next attempt in %s)", cause, backoff)
		if waitCtx(ctx, backoff) {
			return false, nil
		}
		backoff = min(backoff*2, reconnectMax)
		return true, nil
	}

	for attempt := 0; ; attempt++ {
		conn, err := connect(ctx, cfg)
		if err != nil {
			if ctx.Err() != nil {
				log.Println("sidenuclei stopped") // stderr: survives the dead peer
				return nil
			}
			if attempt == 0 {
				return fmt.Errorf("dial sectool at %s: %w", cfg.Socket, err)
			}
			if retry, fatal := reconnectWait(fmt.Errorf("dial %s: %w", cfg.Socket, err)); !retry {
				return fatal
			}
			continue
		}

		served := serveSession(ctx, conn, cfg, s)
		if ctx.Err() != nil {
			log.Println("sidenuclei stopped") // stderr: survives the dead peer
			return nil
		}
		// session over with a live signal ctx: transport drop or host shutdown
		if served >= reconnectStable {
			backoff, outage = reconnectInitial, time.Time{} // healthy session: reset escalation
		}
		if retry, fatal := reconnectWait(fmt.Errorf("session ended after %s", served.Round(time.Second))); !retry {
			return fatal
		}
	}
}

// serveSession runs one registered session: repoints the scanner's conn seams, logs
// the attach, starts the poll loop, and serves until the signal context fires or the
// peer drops. It returns how long the session served and closes the conn before
// returning.
func serveSession(ctx context.Context, conn *sidecar.Conn, cfg Config, s *scanner) time.Duration {
	defer func() { _ = conn.Close() }()

	sessionCtx, cancel := context.WithCancel(ctx) // bounds this session's poll loop, workers, and scans
	defer cancel()

	s.rebind(
		func(ctx context.Context, tool string, params any) (wire.CoreInvokeResult, error) {
			return conn.CoreInvoke(ctx, tool, params)
		},
		func(level, message string, fields map[string]any) { _ = conn.Log(level, message, fields) },
	)

	_ = conn.Log("info", "attached", nil)
	if classes := cfg.enabledInjectionClasses(); len(classes) > 0 {
		_ = conn.Log(logWarn, "active injection fuzzing enabled ("+strings.Join(classes, ",")+"): payloads are sent with captured (often authenticated) requests to "+cfg.FuzzMethods+" endpoints; ensure the target scope is authorized", nil)
	}
	_ = conn.ReportMetrics(map[string]int64{
		"flows_observed":    s.flowsObserved.Load(),
		"endpoints_scanned": s.endpointsScanned.Load(),
		"findings":          s.findings.Load(),
	}, nil)

	h := &handler{cancel: cancel, s: s}
	go pullLoop(sessionCtx, conn, s)

	started := time.Now()
	_ = conn.Serve(sessionCtx, h)
	return time.Since(started)
}
