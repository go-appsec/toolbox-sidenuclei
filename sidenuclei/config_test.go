package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigParse(t *testing.T) {
	t.Parallel()

	t.Run("defaults_resolve", func(t *testing.T) {
		cfg := defaultConfig()
		require.NoError(t, cfg.parse())
		assert.Equal(t, "medium", cfg.fuzzAggression)
		assert.Equal(t, 10*time.Second, cfg.pollInterval)
		assert.Equal(t, 20*time.Minute, cfg.scanTimeout)
		assert.Equal(t, map[string]struct{}{"GET": {}, "POST": {}}, cfg.fuzzMethods)
	})

	t.Run("aggression_precedence", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.fuzzLow, cfg.fuzzHigh = true, true
		require.NoError(t, cfg.parse())
		assert.Equal(t, "high", cfg.fuzzAggression)
	})

	t.Run("explicit_low", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.fuzzLow = true
		require.NoError(t, cfg.parse())
		assert.Equal(t, "low", cfg.fuzzAggression)
	})

	t.Run("nothing_to_scan", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.CVE, cfg.Exposures, cfg.Misconfig, cfg.Tech = false, false, false, false
		cfg.SSRF, cfg.Redirect = false, false
		assert.Error(t, cfg.parse())
	})

	t.Run("bad_poll_interval", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.PollInterval = "nope"
		assert.Error(t, cfg.parse())
	})

	t.Run("bad_scan_timeout", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.ScanTimeout = "nope"
		assert.Error(t, cfg.parse())
	})
}

func TestEngineConfig(t *testing.T) {
	t.Parallel()

	t.Run("defaults", func(t *testing.T) {
		cfg := defaultConfig()
		ec := cfg.engineConfig()
		assert.True(t, ec.Detect)
		assert.Equal(t, []string{"cve", "exposure", "panel", "file", "misconfig", "tech"}, ec.DetectTags)
		assert.True(t, ec.Fuzz)
		assert.Equal(t, []string{"ssrf", "redirect"}, ec.FuzzTags)
		assert.Equal(t, "alpha.oastsrv.net,omega.oastsrv.net,sierra.oastsrv.net,tango.oastsrv.net", ec.OASTServers)
	})

	t.Run("opt_in_class_adds_fuzz_tag", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.SQLi = true
		assert.Contains(t, cfg.engineConfig().FuzzTags, "sqli")
	})

	t.Run("disable_all_detection", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.CVE, cfg.Exposures, cfg.Misconfig, cfg.Tech = false, false, false, false
		ec := cfg.engineConfig()
		assert.False(t, ec.Detect)
		assert.Empty(t, ec.DetectTags)
	})

	t.Run("cve_injection_adds_detect_tags", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.CVEInjection = true
		assert.Subset(t, cfg.engineConfig().DetectTags, []string{"sqli", "rce", "cmdi"})
	})
}

func TestEnabledInjectionClasses(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	assert.Empty(t, cfg.enabledInjectionClasses()) // ssrf/redirect are not injection classes

	cfg.SQLi, cfg.XXE = true, true
	assert.Equal(t, []string{"sqli", "xxe"}, cfg.enabledInjectionClasses())
}

func TestEnabledDetectionNames(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	assert.Equal(t, []string{"cve", "exposures", "misconfig", "tech"}, cfg.enabledDetectionNames())

	cfg.Exposures, cfg.Tech = false, false
	cfg.CVEInjection = true
	assert.Equal(t, []string{"cve", "misconfig", "cve-injection"}, cfg.enabledDetectionNames())
}

func TestEnabledFuzzNames(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	assert.Equal(t, []string{"ssrf", "redirect"}, cfg.enabledFuzzNames())

	cfg.XSS, cfg.CRLF = true, true
	assert.Equal(t, []string{"ssrf", "redirect", "xss", "crlf"}, cfg.enabledFuzzNames())
}

func TestSplitCSV(t *testing.T) {
	t.Parallel()

	assert.Equal(t, []string{"a", "b", "c"}, splitCSV(" a, b ,c ,"))
	assert.Nil(t, splitCSV(""))
	assert.Equal(t, []string{"GET", "POST"}, splitUpperCSV("get,post"))
}
