package main

import (
	"flag"
	"os"

	"github.com/go-appsec/toolbox/sectool/config"
)

// Config holds all runtime configuration for the sidecar.
type Config struct {
	Socket             string // sectool sidecar socket
	Source             string // flows source filter ("proxy")
	PollInterval       string // idle poll cadence (e.g. "1500ms")
	PollLimit          int    // proxy_poll batch size
	FromNow            bool   // seed cursor to newest flow at attach
	NucleiPath         string // nuclei binary path
	NucleiTemplates    string // template selection filter
	NucleiRateLimit    int    // requests/sec cap
	NucleiTimeout      string // per-target scan timeout
	MaxConcurrentScans int    // scan fan-out cap
	InstanceID         string // registration instance ID (self-flow filtering)
}

// defaultConfig returns a Config with all defaults applied.
func defaultConfig() Config {
	return Config{
		Socket:             config.DefaultSidecarSocket(), // Windows: loopback TCP
		Source:             "proxy",
		PollInterval:       "1500ms",
		PollLimit:          200,
		NucleiPath:         "nuclei",
		NucleiRateLimit:    10,
		NucleiTimeout:      "5m",
		MaxConcurrentScans: 2,
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
	fs.StringVar(&cfg.NucleiPath, "nuclei-path", cfg.NucleiPath, "scanner binary path")
	fs.StringVar(&cfg.NucleiTemplates, "nuclei-templates", cfg.NucleiTemplates, "template selection filter")
	fs.IntVar(&cfg.NucleiRateLimit, "nuclei-rate-limit", cfg.NucleiRateLimit, "requests/sec cap")
	fs.StringVar(&cfg.NucleiTimeout, "nuclei-timeout", cfg.NucleiTimeout, "per-target scan timeout")
	fs.IntVar(&cfg.MaxConcurrentScans, "max-concurrent-scans", cfg.MaxConcurrentScans, "scan fan-out cap")
	fs.StringVar(&cfg.InstanceID, "instance-id", cfg.InstanceID, "registration instance ID (auto-generated if empty)")

	if err := fs.Parse(os.Args[1:]); err != nil {
		return cfg // flag.ExitOnError already handled usage/exit
	}

	return cfg
}
