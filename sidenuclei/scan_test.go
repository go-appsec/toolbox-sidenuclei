package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-appsec/toolbox-sidenuclei/sidenuclei/nuclei"
	"github.com/go-appsec/toolbox/sidecar/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeEngine is a scanEngine that emits canned findings and can block in Scan.
type fakeEngine struct {
	findings []nuclei.Finding
	scanned  atomic.Int64
	block    chan struct{} // when non-nil, Scan waits on it (or ctx) before returning

	mu          sync.Mutex
	lastTargets []nuclei.ImportTarget
}

func (f *fakeEngine) Scan(ctx context.Context, targets []nuclei.ImportTarget, cb func(nuclei.Finding)) error {
	f.mu.Lock()
	f.lastTargets = targets
	f.mu.Unlock()
	f.scanned.Add(1)
	if f.block != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-f.block:
		}
	}
	for _, fd := range f.findings {
		cb(fd)
	}
	return nil
}

func (f *fakeEngine) Close() error { return nil }

// flowGetInvoke answers flow_get with the given request detail and notes_save with success.
func flowGetInvoke(url, headers, bodyB64 string) CoreInvoker {
	return func(_ context.Context, tool string, _ any) (wire.CoreInvokeResult, error) {
		if tool == "flow_get" {
			b, _ := json.Marshal(flowRequestDetail{URL: url, ReqHeaders: headers, ReqBody: bodyB64})
			return wire.CoreInvokeResult{Content: string(b)}, nil
		}
		return wire.CoreInvokeResult{Content: `{"note_id":"n"}`}, nil
	}
}

func TestBuildTarget(t *testing.T) {
	t.Parallel()

	cfg := Config{MaxRawRequestBytes: 1 << 20, fuzzMethods: map[string]struct{}{"GET": {}, "POST": {}}}

	t.Run("get_fuzzable", func(t *testing.T) {
		s := newScanner(cfg, flowGetInvoke("http://h/p?x=1", "GET /p?x=1 HTTP/1.1\nHost: h", ""), nil)
		it, ok := s.buildTarget(t.Context(), flowEntry{FlowID: "f", Method: "GET"})
		require.True(t, ok)
		assert.Equal(t, "http://h/p?x=1", it.URL)
		assert.Equal(t, "GET /p?x=1 HTTP/1.1\r\nHost: h\r\n\r\n", it.Raw)
		assert.True(t, it.Fuzzable)
	})

	t.Run("non_fuzz_method", func(t *testing.T) {
		s := newScanner(cfg, flowGetInvoke("http://h/p", "PUT /p HTTP/1.1\nHost: h", ""), nil)
		it, ok := s.buildTarget(t.Context(), flowEntry{FlowID: "f", Method: "PUT"})
		require.True(t, ok)
		assert.False(t, it.Fuzzable)
	})

	t.Run("flow_get_error", func(t *testing.T) {
		invoke := func(_ context.Context, _ string, _ any) (wire.CoreInvokeResult, error) {
			return wire.CoreInvokeResult{}, assert.AnError
		}
		s := newScanner(cfg, invoke, nil)
		_, ok := s.buildTarget(t.Context(), flowEntry{FlowID: "f", Method: "GET"})
		assert.False(t, ok)
	})

	t.Run("unscannable_request", func(t *testing.T) {
		s := newScanner(cfg, flowGetInvoke("http://h/p", "", ""), nil)
		_, ok := s.buildTarget(t.Context(), flowEntry{FlowID: "f", Method: "GET"})
		assert.False(t, ok)
	})
}

func TestRunScan(t *testing.T) {
	t.Parallel()

	cfg := Config{scanTimeout: time.Minute, MaxRawRequestBytes: 1 << 20, fuzzMethods: map[string]struct{}{"POST": {}}}

	t.Run("files_findings", func(t *testing.T) {
		fe := &fakeEngine{findings: []nuclei.Finding{{TemplateID: "T1", Severity: "high"}}}
		body := base64.StdEncoding.EncodeToString([]byte("a=1"))
		s := newScanner(cfg, flowGetInvoke("http://h/p", "POST /p HTTP/1.1\nHost: h", body), fe)

		it, ok := s.buildTarget(t.Context(), flowEntry{FlowID: "f", Method: "POST"})
		require.True(t, ok)
		s.runScan(t.Context(), scanJob{target: it, flowID: "f"})

		assert.Equal(t, int64(1), fe.scanned.Load())
		assert.Equal(t, int64(1), s.endpointsScanned.Load())
		assert.Equal(t, int64(1), s.findings.Load())
		fe.mu.Lock()
		assert.True(t, fe.lastTargets[0].Fuzzable)
		fe.mu.Unlock()
	})

	t.Run("files_under_parent_context", func(t *testing.T) {
		// scanCtx carries the deadline; findings must file under the deadline-free parent
		var noteSeen, noteHasDeadline bool
		invoke := func(ctx context.Context, tool string, _ any) (wire.CoreInvokeResult, error) {
			if tool == "flow_get" {
				b, _ := json.Marshal(flowRequestDetail{URL: "http://h/p", ReqHeaders: "GET /p HTTP/1.1\nHost: h"})
				return wire.CoreInvokeResult{Content: string(b)}, nil
			}
			noteSeen = true
			_, noteHasDeadline = ctx.Deadline()
			return wire.CoreInvokeResult{Content: `{"note_id":"n"}`}, nil
		}
		fe := &fakeEngine{findings: []nuclei.Finding{{TemplateID: "T", MatchedAt: "http://h/p"}}}
		s := newScanner(cfg, invoke, fe)
		it, ok := s.buildTarget(t.Context(), flowEntry{FlowID: "f", Method: "GET"})
		require.True(t, ok)
		s.runScan(t.Context(), scanJob{target: it, flowID: "f"})
		require.True(t, noteSeen)
		assert.False(t, noteHasDeadline)
	})

	t.Run("timeout_returns", func(t *testing.T) {
		fe := &fakeEngine{block: make(chan struct{})} // never released
		short := cfg
		short.scanTimeout = 50 * time.Millisecond
		s := newScanner(short, flowGetInvoke("http://h/p", "POST /p HTTP/1.1\nHost: h", ""), fe)

		it, ok := s.buildTarget(t.Context(), flowEntry{FlowID: "f", Method: "POST"})
		require.True(t, ok)
		done := make(chan struct{})
		go func() {
			s.runScan(t.Context(), scanJob{target: it, flowID: "f"})
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("runScan did not return at timeout")
		}
	})
}

func TestStartWorkers(t *testing.T) {
	t.Parallel()

	cfg := Config{scanTimeout: time.Minute, MaxRawRequestBytes: 1 << 20, fuzzMethods: map[string]struct{}{}}
	job := scanJob{target: nuclei.ImportTarget{URL: "http://h/p"}, flowID: "f"}

	t.Run("drains_queue", func(t *testing.T) {
		fe := &fakeEngine{}
		s := newScanner(cfg, nil, fe)
		s.startWorkers(t.Context(), 2)

		for range 3 {
			s.enqueue(job)
		}
		s.closeQueue()
		assert.Eventually(t, func() bool { return fe.scanned.Load() == 3 }, time.Second, 10*time.Millisecond)
	})

	t.Run("enqueue_never_blocks", func(t *testing.T) {
		release := make(chan struct{})
		fe := &fakeEngine{block: release}
		s := newScanner(cfg, nil, fe)
		s.startWorkers(t.Context(), 1)

		s.enqueue(job) // consumed; the single worker is now blocked in Scan
		s.enqueue(job) // queued behind the blocked worker without blocking the caller
		s.closeQueue()

		// only the first job runs while the worker is blocked
		assert.Never(t, func() bool { return fe.scanned.Load() > 1 }, 50*time.Millisecond, 5*time.Millisecond)

		close(release)
		assert.Eventually(t, func() bool { return fe.scanned.Load() == 2 }, time.Second, 10*time.Millisecond)
	})
}
