package main

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-appsec/toolbox-sidenuclei/sidenuclei/nuclei"
	"github.com/go-appsec/toolbox/sidecar"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// flowEntry mirrors the per-flow fields returned by proxy_poll in flows mode.
type flowEntry struct {
	FlowID         string `json:"flow_id"`
	Method         string `json:"method"`
	Scheme         string `json:"scheme"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Path           string `json:"path"`
	Status         int    `json:"status"`          // kept for future response-body re-check
	ResponseLength int    `json:"response_length"` // kept for future response-body re-check
	Source         string `json:"source"`          // "proxy" | "replay"
}

// proxyPoll is the top-level response from a proxy_poll core_invoke in flows mode.
type proxyPoll struct {
	Flows          []flowEntry `json:"flows"`
	RemainingCount int         `json:"remaining_count"`
}

// CoreInvoker abstracts (*sidecar.Conn).CoreInvoke so tests can feed canned
// responses without a live sectool connection.
type CoreInvoker func(ctx context.Context, tool string, params any) (wire.CoreInvokeResult, error)

// scanJob is a built scan target queued for a worker, tagged with its originating
// flow_id so findings link back to the flow.
type scanJob struct {
	target nuclei.ImportTarget
	flowID string
}

// scanner holds the mutable state for the pull loop: dedup set, scan queue, and the
// core_invoke seam. Counters are atomic because scan workers update them while the
// loop reports metrics.
type scanner struct {
	cfg              Config
	scanned          map[string]struct{}
	flowsObserved    atomic.Int64 // running total of selected flows, reported each tick
	endpointsScanned atomic.Int64 // completed scan runs
	inFlight         atomic.Int64 // scans currently executing
	findings         atomic.Int64 // finding notes filed
	skipped          atomic.Int64 // endpoints dropped as unscannable
	mu               sync.Mutex   // guards queue + closed
	cond             *sync.Cond   // signals queue non-empty / closed
	queue            []scanJob    // unbounded FIFO of built scan targets
	closed           bool         // set at shutdown; workers drain then exit
	notesWarned      atomic.Bool  // one-time warn when sectool lacks --notes
	filedMu          sync.Mutex   // guards filed
	filed            map[string]struct{}
	invoke           CoreInvoker
	engine           scanEngine
	logf             func(level, message string, fields map[string]any)
	lastActivity     int64 // observed+skipped at the last metrics report (poll goroutine only)
}

func newScanner(cfg Config, invoke CoreInvoker, engine scanEngine) *scanner {
	s := &scanner{
		cfg:     cfg,
		scanned: make(map[string]struct{}),
		filed:   make(map[string]struct{}),
		invoke:  invoke,
		engine:  engine,
	}
	s.cond = sync.NewCond(&s.mu)
	s.logf = func(string, string, map[string]any) {} // default no-op; run installs the conn-backed logger
	return s
}

// pullLoop is the proxy_poll cursor loop. It observes every flow after the cursor
// exactly once, filters replay and duplicate flows, and hands each unique in-scope
// endpoint to the scan worker pool. The scanner is shared with the status tool
// handler, so it is constructed by the caller.
func pullLoop(ctx context.Context, conn *sidecar.Conn, s *scanner) {
	cfg := s.cfg
	s.startWorkers(ctx, cfg.MaxConcurrentScans) // ctx cancellation stops in-progress scans
	defer s.closeQueue()                        // stop workers once the loop exits (on shutdown)

	var cursor string // empty = from the beginning; never "last"
	if cfg.FromNow {
		cursor = s.seedFromNow(ctx)
		if ctx.Err() != nil {
			return
		}
	}

	for {
		poll, ok := s.poll(ctx, cursor)
		if !ok {
			if waitCtx(ctx, cfg.pollInterval) { // back off; keep cursor
				return
			}
			continue
		}

		var selected int
		for _, f := range poll.Flows {
			cursor = f.FlowID // advance past everything seen

			if s.skip(f) {
				continue
			}
			// build the target here so a queued flow's body is captured before
			// sectool can evict it; workers only run the engine
			it, ok := s.buildTarget(ctx, f)
			if !ok {
				s.skipped.Add(1)
				continue
			}
			s.enqueue(scanJob{target: it, flowID: f.FlowID})
			selected++
		}

		if selected > 0 {
			s.flowsObserved.Add(int64(selected))
			s.logf(logInfo, "poll tick", map[string]any{
				"flows_selected": selected,
				"cursor":         cursor,
			})
		}
		// report only when observed+skipped changed, so idle ticks don't repeat the line
		if activity := s.flowsObserved.Load() + s.skipped.Load(); activity != s.lastActivity {
			s.lastActivity = activity
			_ = conn.ReportMetrics(map[string]int64{
				"flows_observed":    s.flowsObserved.Load(),
				"endpoints_scanned": s.endpointsScanned.Load(),
				"findings":          s.findings.Load(),
				"skipped":           s.skipped.Load(),
			}, nil)
		}

		if waitCtx(ctx, remainingCountBackoff(poll.RemainingCount, cfg.pollInterval)) {
			return
		}
	}
}

// poll executes one proxy_poll call with the given cursor and returns the parsed
// result. On error it leaves the cursor untouched (caller backs off) and returns false.
func (s *scanner) poll(ctx context.Context, cursor string) (proxyPoll, bool) {
	args := map[string]any{
		"output_mode": "flows",
		"since":       cursor,
		"source":      s.cfg.Source,
		"limit":       s.cfg.PollLimit,
	}

	res, err := s.invoke(ctx, "proxy_poll", args)
	if err != nil || res.IsError {
		return proxyPoll{}, false
	}

	var poll proxyPoll
	if err := json.Unmarshal([]byte(res.Content), &poll); err != nil {
		return proxyPoll{}, false
	}
	return poll, true
}

// seedFromNow performs one initial poll with no cursor and returns the newest
// flow_id so that only attach-onward traffic is observed. Returns empty on
// failure or when history is empty.
func (s *scanner) seedFromNow(ctx context.Context) string {
	poll, ok := s.poll(ctx, "")
	if !ok || len(poll.Flows) == 0 {
		return ""
	}
	return poll.Flows[len(poll.Flows)-1].FlowID
}

// remainingCountBackoff returns the wait before the next poll: zero when there
// are more flows to drain (loop runs immediately), else cfg.PollInterval.
func remainingCountBackoff(remaining int, interval time.Duration) time.Duration {
	if remaining > 0 {
		return 0 // drain without sleeping
	}
	return interval
}

// waitCtx sleeps for d or until ctx is done; returns true if the context was cancelled.
func waitCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return true
	case <-timer.C:
		return false
	}
}

// endpointKey builds a stable dedup key from the request side of a flow entry.
// Query values are dropped but parameter names are kept, so endpoints differing
// only in values collapse while distinct parameter sets stay separate scan targets.
func endpointKey(f flowEntry) string {
	return f.Method + " " + f.Scheme + "://" + f.Host + ":" + strconv.Itoa(f.Port) + pathKey(f.Path)
}

// pathKey returns path with the query reduced to sorted, de-duplicated parameter names.
func pathKey(path string) string {
	base, query, found := strings.Cut(path, "?")
	if !found || query == "" {
		return base
	}
	var names []string
	seen := make(map[string]struct{})
	for _, p := range strings.Split(query, "&") {
		name, _, _ := strings.Cut(p, "=")
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	slices.Sort(names)
	return base + "?" + strings.Join(names, "&")
}

// enqueue appends a built job without blocking, so the poll loop keeps polling while
// scans run. The queue is bounded only by unique in-scope endpoints (skip dedups first).
func (s *scanner) enqueue(j scanJob) {
	s.mu.Lock()
	s.queue = append(s.queue, j)
	s.mu.Unlock()
	s.cond.Signal()
}

// queueDepth returns the number of built jobs waiting for a worker.
func (s *scanner) queueDepth() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.queue)
}

// dequeue returns the next job, waiting when empty. Returns false once the queue is
// closed and drained.
func (s *scanner) dequeue() (scanJob, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.queue) == 0 && !s.closed {
		s.cond.Wait()
	}
	if len(s.queue) == 0 {
		return scanJob{}, false
	}
	j := s.queue[0]
	s.queue = s.queue[1:]
	return j, true
}

// closeQueue stops workers once the pending queue drains (shutdown).
func (s *scanner) closeQueue() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.cond.Broadcast()
}

// skip reports whether f should not be scanned: replay traffic or an endpoint
// already selected. Scans run directly (never through the proxy), so nuclei's own
// probes never enter proxy history and need no self-scan guard.
func (s *scanner) skip(f flowEntry) bool {
	if f.Source == "replay" {
		return true // replay flows never enter the scan path
	}
	key := endpointKey(f)
	if _, seen := s.scanned[key]; seen {
		return true
	}
	s.scanned[key] = struct{}{}
	return false
}
