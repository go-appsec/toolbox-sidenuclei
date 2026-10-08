//go:build unix

package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol"
	scsidecar "github.com/go-appsec/toolbox/sectool/service/proxy/protocol/sidecar"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// shortenReconnect swaps the reconnect pacing for test-scale values, restoring the
// originals at cleanup. Tests using it are not parallel (shared package vars).
func shortenReconnect(t *testing.T, initial, max, stable, window time.Duration) {
	t.Helper()

	oi, om, ostable, owindow := reconnectInitial, reconnectMax, reconnectStable, reconnectWindow
	reconnectInitial, reconnectMax, reconnectStable, reconnectWindow = initial, max, stable, window
	t.Cleanup(func() { reconnectInitial, reconnectMax, reconnectStable, reconnectWindow = oi, om, ostable, owindow })
}

// testScanner returns a scanner wired for serveForever tests: fast idle polls and no
// engine, since the no-op host never yields flows to scan.
func testScanner() *scanner {
	return newScanner(Config{pollInterval: 50 * time.Millisecond}, nil, nil)
}

// startHost brings up a standalone sidecar host on socket with no-op backends. The
// listener is returned so a test can drop the host mid-run (t.Cleanup closes it).
func startHost(t *testing.T, socket string) (*scsidecar.Listener, *scsidecar.Manager) {
	t.Helper()

	cfg := scsidecar.Config{Socket: socket}
	mgr := scsidecar.NewManager(cfg, &protocol.Registry{}, noopFlowSink{}, noopCore{}, noopRules{})
	lst, err := scsidecar.NewListener(t.Context(), cfg, mgr)
	require.NoError(t, err)
	go func() { _ = lst.Serve() }()
	t.Cleanup(func() { _ = lst.Close(context.Background()) })
	return lst, mgr
}

// serveAsync runs serveForever in a goroutine, returning the completion channel and
// the signal-context cancel.
func serveAsync(t *testing.T, socket string) (chan error, context.CancelFunc) {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	errCh := make(chan error, 1)
	go func() { errCh <- serveForever(ctx, Config{Socket: socket}, testScanner()) }()
	t.Cleanup(cancel)
	return errCh, cancel
}

func TestServeForever(t *testing.T) { // not parallel: shortens the shared pacing vars
	t.Run("reconnects_after_host_restart", func(t *testing.T) {
		shortenReconnect(t, 5*time.Millisecond, 20*time.Millisecond, 50*time.Millisecond, 5*time.Second)

		socket := filepath.Join(t.TempDir(), "sidecar.sock")
		lst1, mgr1 := startHost(t, socket)
		errCh, cancel := serveAsync(t, socket)

		require.Eventually(t, func() bool { return mgr1.Count() == 1 }, 2*time.Second, 5*time.Millisecond)

		// a sectool restart: the session drops and the socket rebinds under a fresh host
		require.NoError(t, lst1.Close(context.Background()))
		require.Eventually(t, func() bool { return mgr1.Count() == 0 }, 2*time.Second, 5*time.Millisecond)
		_, mgr2 := startHost(t, socket)

		require.Eventually(t, func() bool { return mgr2.Count() == 1 }, 5*time.Second, 10*time.Millisecond)

		cancel()
		select {
		case err := <-errCh:
			require.NoError(t, err) // signal exit stays clean
		case <-time.After(2 * time.Second):
			t.Fatal("serveForever did not return on cancel")
		}
	})

	t.Run("first_dial_failure_fatal", func(t *testing.T) {
		socket := filepath.Join(t.TempDir(), "missing.sock")

		// nothing is listening and no session ever served: a startup problem, not an outage
		err := serveForever(t.Context(), Config{Socket: socket}, testScanner())
		require.ErrorContains(t, err, "dial sectool")
	})

	t.Run("window_exhaustion_exits_nonzero", func(t *testing.T) {
		shortenReconnect(t, 5*time.Millisecond, 20*time.Millisecond, 50*time.Millisecond, 150*time.Millisecond)

		socket := filepath.Join(t.TempDir(), "sidecar.sock")
		lst, mgr := startHost(t, socket)
		errCh, _ := serveAsync(t, socket)

		require.Eventually(t, func() bool { return mgr.Count() == 1 }, 2*time.Second, 5*time.Millisecond)
		require.NoError(t, lst.Close(context.Background())) // the host is gone for good

		select {
		case err := <-errCh:
			require.ErrorContains(t, err, "no healthy sectool session") // exit nonzero
		case <-time.After(3 * time.Second):
			t.Fatal("serveForever did not exhaust the outage window")
		}
	})
}

func TestScannerRebind(t *testing.T) {
	t.Parallel()

	t.Run("core_invoke_follows_rebind", func(t *testing.T) {
		first := func(_ context.Context, _ string, _ any) (wire.CoreInvokeResult, error) {
			return wire.CoreInvokeResult{Content: "one"}, nil
		}
		second := func(_ context.Context, _ string, _ any) (wire.CoreInvokeResult, error) {
			return wire.CoreInvokeResult{Content: "two"}, nil
		}

		s := newScanner(Config{}, first, nil)
		res, err := s.coreInvoke(t.Context(), "x", nil)
		require.NoError(t, err)
		assert.Equal(t, "one", res.Content)

		var logged string
		s.rebind(second, func(_, message string, _ map[string]any) { logged = message })
		res, err = s.coreInvoke(t.Context(), "x", nil)
		require.NoError(t, err)
		assert.Equal(t, "two", res.Content)

		s.log(logWarn, "hi", nil)
		assert.Equal(t, "hi", logged)
	})

	t.Run("unbound_invoke_errors", func(t *testing.T) {
		s := newScanner(Config{}, nil, nil)
		_, err := s.coreInvoke(t.Context(), "x", nil)
		assert.Error(t, err)
	})

	t.Run("reset_queue_drops_stale_jobs", func(t *testing.T) {
		s := newScanner(Config{}, nil, nil)
		s.enqueue(scanJob{flowID: "stale"})
		s.closeQueue()

		s.resetQueue()
		s.mu.Lock()
		assert.False(t, s.closed)
		assert.Empty(t, s.queue)
		s.mu.Unlock()
	})
}

// no-op host backends: no flows, no core tools, no rules

type noopFlowSink struct{}

func (noopFlowSink) Store(*types.Flow) string { return "" }
func (noopFlowSink) Complete(string, *types.Message, time.Time, map[string]any) bool {
	return false
}
func (noopFlowSink) SetInvokedBy(string, string) bool { return false }
func (noopFlowSink) Get(string) (*types.Flow, bool)   { return nil, false }
func (noopFlowSink) ShouldCapture(*types.Flow) bool   { return true }

type noopCore struct{}

func (noopCore) CoreInvoke(context.Context, string, json.RawMessage) (string, bool, error) {
	return "", false, nil
}
func (noopCore) CoreToolNames() []string { return []string{"proxy_poll", "flow_get"} }

type noopRules struct{}

func (noopRules) RuleSnapshot(string) []wire.Rule { return nil }
