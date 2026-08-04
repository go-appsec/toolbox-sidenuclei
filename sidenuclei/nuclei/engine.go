package nuclei

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-analyze/bulk"
	sdk "github.com/projectdiscovery/nuclei/v3/lib"
	nucleiconfig "github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/installer"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// DefaultOASTServers are the interactsh-lite servers used for out-of-band testing.
const DefaultOASTServers = "alpha.oastsrv.net,omega.oastsrv.net,sierra.oastsrv.net,tango.oastsrv.net"

// detectExcludeTags are dropped from the detection pass regardless of selection.
var detectExcludeTags = []string{"dos", "intrusive"}

// EngineConfig configures the two scan passes. Detect runs standard detection
// templates; Fuzz runs active DAST templates.
type EngineConfig struct {
	Detect     bool
	DetectTags []string

	Fuzz               bool
	FuzzTags           []string
	FuzzAggression     string // must be non-empty (low/medium/high)
	FuzzParamFrequency int
	FuzzScope          []string
	FuzzOutOfScope     []string

	OASTServers string // comma-separated interactsh servers; empty disables OAST
	OASTToken   string

	TemplatesDir string // empty = nuclei config dir
	RateLimit    int
	Concurrency  int
}

// Engine holds the warm nuclei engines and the temp dir for import files. Build one
// at startup with New and reuse it for every Scan.
type Engine struct {
	detect *passEngine
	fuzz   *passEngine
	dir    string
	seq    atomic.Uint64
	once   sync.Once // guards Close against concurrent or repeated invocation
}

// New provisions templates, then constructs the enabled scan passes. Returns an
// error when templates cannot be installed or an engine fails to build.
func New(ctx context.Context, cfg EngineConfig) (*Engine, error) {
	if cfg.TemplatesDir != "" {
		nucleiconfig.DefaultConfig.SetTemplatesDir(cfg.TemplatesDir)
	}
	if err := (&installer.TemplateManager{}).FreshInstallIfNotExists(); err != nil {
		return nil, fmt.Errorf("install nuclei-templates: %w", err)
	}

	dir, err := os.MkdirTemp("", "sidenuclei-")
	if err != nil {
		return nil, err
	}
	e := &Engine{dir: dir}

	if cfg.Detect {
		filters := sdk.TemplateFilters{
			Tags:        cfg.DetectTags,
			ExcludeTags: detectExcludeTags,
		}
		if e.detect, err = buildPass(ctx, "detect", false, filters, cfg); err != nil {
			_ = e.Close()
			return nil, err
		}
	}
	if cfg.Fuzz {
		filters := sdk.TemplateFilters{Tags: cfg.FuzzTags}
		if e.fuzz, err = buildPass(ctx, "fuzz", true, filters, cfg); err != nil {
			_ = e.Close()
			return nil, err
		}
	}
	return e, nil
}

// Scan runs each enabled pass over targets, serialized per engine, invoking cb for
// every matched finding. Detection runs on all targets; the DAST pass runs only on
// Fuzzable ones. Passes run sequentially; errors from both are joined.
func (e *Engine) Scan(ctx context.Context, targets []ImportTarget, cb func(Finding)) error {
	var errs []error
	if e.detect != nil {
		if err := e.runPass(ctx, e.detect, targets, cb); err != nil {
			errs = append(errs, fmt.Errorf("detect: %w", err))
		}
	}
	if e.fuzz != nil {
		fuzzable := bulk.SliceFilter(func(t ImportTarget) bool { return t.Fuzzable }, targets)
		if len(fuzzable) > 0 {
			if err := e.runPass(ctx, e.fuzz, fuzzable, cb); err != nil {
				errs = append(errs, fmt.Errorf("fuzz: %w", err))
			}
		}
	}
	return errors.Join(errs...)
}

// runPass writes targets to a jsonl file and executes one pass over it.
func (e *Engine) runPass(ctx context.Context, pe *passEngine, targets []ImportTarget, cb func(Finding)) error {
	path, err := e.writeTargets(targets)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(path) }()
	return pe.scan(ctx, path, cb)
}

// Close shuts down both engines and removes the temp dir. Idempotent: safe to call
// again or concurrently (e.g. from OnShutdown and deferred run cleanup).
func (e *Engine) Close() error {
	var err error
	e.once.Do(func() {
		if e.detect != nil {
			e.detect.e.Close()
		}
		if e.fuzz != nil {
			e.fuzz.e.Close()
		}
		err = os.RemoveAll(e.dir)
	})
	return err
}

// proxifyDoc is one jsonl import document; nuclei consumes only url + request.raw.
type proxifyDoc struct {
	URL     string `json:"url"`
	Request struct {
		Raw      string `json:"raw"`
		Endpoint string `json:"endpoint"`
	} `json:"request"`
}

func (e *Engine) writeTargets(targets []ImportTarget) (string, error) {
	path := filepath.Join(e.dir, "targets-"+strconv.FormatUint(e.seq.Add(1), 10)+".jsonl")
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	for _, t := range targets {
		var doc proxifyDoc
		doc.URL = t.URL
		doc.Request.Raw = t.Raw
		doc.Request.Endpoint = t.URL
		if err := enc.Encode(doc); err != nil {
			return "", err
		}
	}
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// passEngine wraps one nuclei engine with a serialized execute and a single
// registered dispatcher callback (the lib appends callbacks per execute).
type passEngine struct {
	name       string
	e          *sdk.NucleiEngine
	mu         sync.Mutex // serializes execute (LoadTargets + ExecuteCallback)
	registered bool
	cur        atomic.Pointer[func(Finding)] // live only during an execute; read lock-free by dispatch
}

func (pe *passEngine) dispatch(ev *output.ResultEvent) {
	if ev == nil || !ev.MatcherStatus {
		return
	}
	if cb := pe.cur.Load(); cb != nil {
		(*cb)(mapEvent(pe.name, ev))
	}
}

func (pe *passEngine) scan(ctx context.Context, path string, cb func(Finding)) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	if err := pe.e.LoadTargetsWithHttpData(path, "jsonl"); err != nil {
		return err
	}
	pe.cur.Store(&cb)
	defer pe.cur.Store(nil)

	// nuclei appends the callback to its list on every ExecuteCallbackWithCtx, so
	// register the dispatcher exactly once; later executes reuse it and pass none
	if !pe.registered {
		pe.registered = true
		return pe.e.ExecuteCallbackWithCtx(ctx, pe.dispatch)
	}
	return pe.e.ExecuteCallbackWithCtx(ctx)
}

// buildPass constructs one nuclei engine with the given filters, enabling DAST for
// the fuzz pass and setting fuzz/rate tunables that have no dedicated option.
func buildPass(ctx context.Context, name string, dast bool, filters sdk.TemplateFilters, cfg EngineConfig) (*passEngine, error) {
	opts := []sdk.NucleiSDKOptions{
		sdk.DisableUpdateCheck(),
		sdk.WithTemplateFilters(filters),
		interactshOption(cfg),
	}
	if dast {
		opts = append(opts, sdk.DASTMode())
	}

	e, err := sdk.NewNucleiEngineCtx(ctx, opts...)
	if err != nil {
		return nil, err
	}

	o := e.Options()
	if cfg.RateLimit > 0 {
		o.RateLimit = cfg.RateLimit
	}
	if cfg.Concurrency > 0 {
		o.TemplateThreads = cfg.Concurrency
		o.BulkSize = cfg.Concurrency
	}
	if dast {
		o.FuzzAggressionLevel = cfg.FuzzAggression
		o.FuzzParamFrequency = cfg.FuzzParamFrequency
		o.Scope = cfg.FuzzScope
		o.OutOfScope = cfg.FuzzOutOfScope
	}
	return &passEngine{name: name, e: e}, nil
}

// interactshOption returns the OAST config; empty OASTServers hard-disables the
// interactsh client so no probes beacon to public servers.
func interactshOption(cfg EngineConfig) sdk.NucleiSDKOptions {
	io := sdk.InteractshOpts{
		CacheSize:      5000,
		Eviction:       60 * time.Second,
		PollDuration:   5 * time.Second,
		CooldownPeriod: 5 * time.Second,
	}
	if cfg.OASTServers == "" {
		io.NoInteractsh = true
	} else {
		io.ServerURL = cfg.OASTServers
		io.Authorization = cfg.OASTToken
	}
	return sdk.WithInteractshOptions(io)
}
