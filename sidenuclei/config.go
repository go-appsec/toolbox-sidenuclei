package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-analyze/bulk"

	"github.com/go-appsec/toolbox-sidenuclei/sidenuclei/nuclei"
	"github.com/go-appsec/toolbox/sectool/config"
)

// Config holds all runtime configuration for the sidecar. The scan engines are
// derived from which coverage categories are enabled, not set directly.
type Config struct {
	Socket             string // sectool sidecar socket
	Source             string // flows source filter ("proxy")
	PollInterval       string // idle poll cadence (e.g. "10s")
	PollLimit          int    // proxy_poll batch size
	FromNow            bool   // seed cursor to newest flow at attach
	MaxConcurrentScans int    // in-flight scan cap

	// detection coverage (default on; --disable-*)
	CVE          bool
	Exposures    bool
	Misconfig    bool
	Tech         bool
	CVEInjection bool // known-CVE injection checks (default off)

	// fuzzing coverage
	SSRF     bool // default on
	Redirect bool // default on
	SQLi     bool // default off
	XSS      bool // default off
	CMDi     bool // default off
	SSTI     bool // default off
	XXE      bool // default off
	CRLF     bool // default off

	// fuzz behavior
	FuzzMethods        string // HTTP methods eligible for fuzzing (CSV)
	FuzzParamFrequency int    // skip a param after this many occurrences
	FuzzScope          string // in-scope URL regexes (CSV)
	FuzzOutOfScope     string // out-of-scope URL regexes (CSV)

	// OAST / interactsh (our servers by default; empty disables)
	OASTServers string // comma-separated interactsh servers
	OASTToken   string // interactsh auth token

	// engine / operational
	TemplatesDir       string // nuclei templates dir ("" = pd config dir)
	RateLimit          int    // requests/sec cap per engine
	Concurrency        int    // nuclei template/bulk concurrency
	ScanTimeout        string // per-endpoint scan timeout
	MaxRawRequestBytes int    // skip fuzzing requests larger than this

	fuzzLow, fuzzMedium, fuzzHigh bool // aggression selector flags

	pollInterval   time.Duration       // parsed PollInterval
	scanTimeout    time.Duration       // parsed ScanTimeout
	fuzzMethods    map[string]struct{} // parsed FuzzMethods (upper-cased)
	fuzzAggression string              // resolved from the aggression flags
}

// defaultConfig returns a Config with all defaults applied.
func defaultConfig() Config {
	return Config{
		Socket:             config.DefaultSidecarSocket(), // Windows: loopback TCP
		Source:             "proxy",
		PollInterval:       "10s",
		PollLimit:          200,
		MaxConcurrentScans: 1,

		CVE:       true,
		Exposures: true,
		Misconfig: true,
		Tech:      true,

		SSRF:     true,
		Redirect: true,

		FuzzMethods:        "GET,POST",
		FuzzParamFrequency: 10,

		OASTServers: nuclei.DefaultOASTServers,

		RateLimit:          10,
		Concurrency:        25,
		ScanTimeout:        "20m",
		MaxRawRequestBytes: 262144,
	}
}

// parseFlags parses CLI flags into a Config. Returns the resolved config or exits on error.
func parseFlags() Config {
	cfg := defaultConfig()

	fs := flag.NewFlagSet("sidenuclei", flag.ExitOnError)
	fs.StringVar(&cfg.Socket, "sidecar-socket", cfg.Socket, "sectool sidecar socket")
	fs.StringVar(&cfg.Source, "source", cfg.Source, "flows source filter (feedback-loop guard)")
	fs.StringVar(&cfg.PollInterval, "poll-interval", cfg.PollInterval, "idle poll cadence when cursor is drained")
	fs.IntVar(&cfg.PollLimit, "poll-limit", cfg.PollLimit, "proxy_poll batch size")
	fs.BoolVar(&cfg.FromNow, "from-now", cfg.FromNow, "seed cursor to newest flow at attach (skip backlog)")
	fs.IntVar(&cfg.MaxConcurrentScans, "max-concurrent-scans", cfg.MaxConcurrentScans, "in-flight scan cap (engine execute is serialized)")

	// detection coverage: on by default, --disable-* to turn off
	disable(fs, "disable-cve", "disable CVE detection", &cfg.CVE)
	disable(fs, "disable-exposures", "disable exposure/panel/file detection", &cfg.Exposures)
	disable(fs, "disable-misconfig", "disable misconfiguration detection", &cfg.Misconfig)
	disable(fs, "disable-tech", "disable technology/version fingerprinting", &cfg.Tech)
	fs.BoolVar(&cfg.CVEInjection, "cve-injection", cfg.CVEInjection, "enable known-CVE injection checks")

	// fuzzing coverage: ssrf/redirect on by default, injection classes opt-in
	disable(fs, "disable-ssrf", "disable SSRF fuzzing", &cfg.SSRF)
	disable(fs, "disable-redirect", "disable open-redirect fuzzing", &cfg.Redirect)
	fs.BoolVar(&cfg.SQLi, "sqli", cfg.SQLi, "enable SQL injection fuzzing")
	fs.BoolVar(&cfg.XSS, "xss", cfg.XSS, "enable cross-site scripting fuzzing")
	fs.BoolVar(&cfg.CMDi, "cmdi", cfg.CMDi, "enable command injection fuzzing")
	fs.BoolVar(&cfg.SSTI, "ssti", cfg.SSTI, "enable server-side template injection fuzzing")
	fs.BoolVar(&cfg.XXE, "xxe", cfg.XXE, "enable XXE fuzzing")
	fs.BoolVar(&cfg.CRLF, "crlf", cfg.CRLF, "enable CRLF injection fuzzing")

	fs.BoolVar(&cfg.fuzzLow, "fuzz-low", false, "low fuzz payload volume")
	fs.BoolVar(&cfg.fuzzMedium, "fuzz-medium", false, "medium fuzz payload volume (default)")
	fs.BoolVar(&cfg.fuzzHigh, "fuzz-high", false, "high fuzz payload volume")

	fs.StringVar(&cfg.FuzzMethods, "fuzz-methods", cfg.FuzzMethods, "HTTP methods eligible for fuzzing (CSV)")
	fs.IntVar(&cfg.FuzzParamFrequency, "fuzz-param-frequency", cfg.FuzzParamFrequency, "skip a parameter after this many occurrences")
	fs.StringVar(&cfg.FuzzScope, "fuzz-scope", cfg.FuzzScope, "in-scope URL regexes for the fuzzer (CSV)")
	fs.StringVar(&cfg.FuzzOutOfScope, "fuzz-out-scope", cfg.FuzzOutOfScope, "out-of-scope URL regexes for the fuzzer (CSV)")

	fs.StringVar(&cfg.OASTServers, "oast-servers", cfg.OASTServers, "interactsh servers for out-of-band testing (CSV; empty disables OAST)")
	fs.StringVar(&cfg.OASTToken, "oast-token", cfg.OASTToken, "interactsh auth token (for protected servers)")

	fs.StringVar(&cfg.TemplatesDir, "templates-dir", cfg.TemplatesDir, "nuclei templates dir (empty = pd config dir, auto-installed)")
	fs.IntVar(&cfg.RateLimit, "rate-limit", cfg.RateLimit, "requests/sec cap per engine")
	fs.IntVar(&cfg.Concurrency, "concurrency", cfg.Concurrency, "nuclei template/bulk concurrency")
	fs.StringVar(&cfg.ScanTimeout, "scan-timeout", cfg.ScanTimeout, "per-endpoint scan timeout")
	fs.IntVar(&cfg.MaxRawRequestBytes, "max-raw-request-bytes", cfg.MaxRawRequestBytes, "skip requests whose raw form exceeds this")

	if err := fs.Parse(os.Args[1:]); err != nil {
		return cfg // flag.ExitOnError already handled usage/exit
	}

	return cfg
}

// disable registers a --disable-<name> flag that clears *on when supplied.
func disable(fs *flag.FlagSet, name, usage string, on *bool) {
	fs.BoolFunc(name, usage, func(string) error {
		*on = false
		return nil
	})
}

// parse validates and resolves derived config: poll/scan durations, the fuzz
// aggression level, and the fuzz method set. Returns an actionable error on bad input.
func (c *Config) parse() error {
	switch {
	case c.fuzzHigh:
		c.fuzzAggression = "high"
	case c.fuzzLow:
		c.fuzzAggression = "low"
	default:
		c.fuzzAggression = "medium" // default; also explicit --fuzz-medium
	}

	if !c.detectEnabled() && !c.fuzzEnabled() {
		return errors.New("nothing to scan: enable at least one detection or fuzzing category")
	}

	pollInterval, err := time.ParseDuration(c.PollInterval)
	if err != nil {
		return fmt.Errorf("invalid --poll-interval %q: %w", c.PollInterval, err)
	}
	c.pollInterval = pollInterval

	scanTimeout, err := time.ParseDuration(c.ScanTimeout)
	if err != nil {
		return fmt.Errorf("invalid --scan-timeout %q: %w", c.ScanTimeout, err)
	}
	c.scanTimeout = scanTimeout

	c.fuzzMethods = bulk.SliceToSet(splitUpperCSV(c.FuzzMethods))

	return nil
}

// category pairs a coverage toggle with the nuclei tags it selects.
type category struct {
	on   bool
	tags []string
}

func (c *Config) detectCategories() []category {
	return []category{
		{c.CVE, []string{"cve"}},
		{c.Exposures, []string{"exposure", "panel", "file"}},
		{c.Misconfig, []string{"misconfig"}},
		{c.Tech, []string{"tech"}},
		{c.CVEInjection, []string{"sqli", "rce", "cmdi"}},
	}
}

func (c *Config) fuzzCategories() []category {
	return []category{
		{c.SSRF, []string{"ssrf"}},
		{c.Redirect, []string{"redirect"}},
		{c.SQLi, []string{"sqli"}},
		{c.XSS, []string{"xss"}},
		{c.CMDi, []string{"cmdi"}},
		{c.SSTI, []string{"ssti"}},
		{c.XXE, []string{"xxe"}},
		{c.CRLF, []string{"crlf"}},
	}
}

// detectEnabled reports whether any detection category is on.
func (c *Config) detectEnabled() bool { return len(tagsOf(c.detectCategories())) > 0 }

// fuzzEnabled reports whether any fuzzing category is on.
func (c *Config) fuzzEnabled() bool { return len(tagsOf(c.fuzzCategories())) > 0 }

// enabledInjectionClasses returns the names of the opt-in active-injection classes
// that are enabled, for the startup safety warning.
func (c *Config) enabledInjectionClasses() []string {
	classes := []struct {
		on   bool
		name string
	}{
		{c.SQLi, "sqli"}, {c.XSS, "xss"}, {c.CMDi, "cmdi"},
		{c.SSTI, "ssti"}, {c.XXE, "xxe"}, {c.CRLF, "crlf"},
		{c.CVEInjection, "cve-injection"},
	}
	var out []string
	for _, cl := range classes {
		if cl.on {
			out = append(out, cl.name)
		}
	}
	return out
}

// engineConfig projects the sidecar Config onto the nuclei engine configuration.
func (c *Config) engineConfig() nuclei.EngineConfig {
	detectTags := tagsOf(c.detectCategories())
	fuzzTags := tagsOf(c.fuzzCategories())
	return nuclei.EngineConfig{
		Detect:     len(detectTags) > 0,
		DetectTags: detectTags,

		Fuzz:               len(fuzzTags) > 0,
		FuzzTags:           fuzzTags,
		FuzzAggression:     c.fuzzAggression,
		FuzzParamFrequency: c.FuzzParamFrequency,
		FuzzScope:          splitCSV(c.FuzzScope),
		FuzzOutOfScope:     splitCSV(c.FuzzOutOfScope),

		OASTServers: c.OASTServers,
		OASTToken:   c.OASTToken,

		TemplatesDir: c.TemplatesDir,
		RateLimit:    c.RateLimit,
		Concurrency:  c.Concurrency,
	}
}

// tagsOf returns the de-duplicated tags of the enabled categories.
func tagsOf(cats []category) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, cat := range cats {
		if !cat.on {
			continue
		}
		for _, t := range cat.tags {
			if _, ok := seen[t]; ok {
				continue
			}
			seen[t] = struct{}{}
			out = append(out, t)
		}
	}
	return out
}

// splitCSV splits a comma-separated list into trimmed, non-empty values.
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// splitUpperCSV is splitCSV with each value upper-cased (for HTTP method matching).
func splitUpperCSV(s string) []string {
	out := splitCSV(s)
	for i, p := range out {
		out[i] = strings.ToUpper(p)
	}
	return out
}
