package main

import (
	"encoding/json"
	"testing"

	"github.com/go-appsec/toolbox/sidecar/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScannerStatus(t *testing.T) {
	t.Parallel()

	t.Run("reflects_counters_and_queue", func(t *testing.T) {
		s := newScanner(defaultConfig(), nil, nil)
		s.flowsObserved.Store(40)
		s.endpointsScanned.Store(33)
		s.skipped.Store(4)
		s.findings.Store(7)
		s.inFlight.Store(2)
		s.enqueue(scanJob{})
		s.enqueue(scanJob{})
		s.enqueue(scanJob{})

		rep := s.status()
		assert.True(t, rep.Scanning)
		assert.Equal(t, int64(2), rep.ActiveScans)
		assert.Equal(t, 3, rep.QueueDepth)
		assert.Equal(t, int64(40), rep.FlowsObserved)
		assert.Equal(t, int64(33), rep.EndpointsScanned)
		assert.Equal(t, int64(4), rep.Skipped)
		assert.Equal(t, int64(7), rep.FindingsFiled)
		assert.True(t, rep.NotesFilingOK)
		assert.Equal(t, []string{"cve", "exposures", "misconfig", "tech"}, rep.Coverage.Detection)
		assert.Equal(t, []string{"ssrf", "redirect"}, rep.Coverage.Fuzzing)
	})

	t.Run("idle_is_not_scanning", func(t *testing.T) {
		rep := newScanner(defaultConfig(), nil, nil).status()
		assert.False(t, rep.Scanning)
		assert.Zero(t, rep.ActiveScans)
		assert.Zero(t, rep.QueueDepth)
	})

	t.Run("notes_filing_flips_on_warn", func(t *testing.T) {
		s := newScanner(defaultConfig(), nil, nil)
		s.notesWarned.Store(true)
		assert.False(t, s.status().NotesFilingOK)
	})
}

func TestStatusDescription(t *testing.T) {
	t.Parallel()

	cov := coverageInfo{Detection: []string{"cve", "tech"}, Fuzzing: []string{"ssrf"}}

	t.Run("lists_coverage_and_notes_reminder", func(t *testing.T) {
		d := statusDescription(cov, true)
		assert.Contains(t, d, "detection: cve, tech")
		assert.Contains(t, d, "fuzzing: ssrf")
		assert.Contains(t, d, "check notes for scan results")
		assert.NotContains(t, d, "warning")
	})

	t.Run("warns_when_notes_unavailable", func(t *testing.T) {
		d := statusDescription(cov, false)
		assert.Contains(t, d, "without --notes")
	})
}

func TestHandlerOnInvokeTool(t *testing.T) {
	t.Parallel()

	t.Run("nuclei_status_returns_result", func(t *testing.T) {
		s := newScanner(defaultConfig(), nil, nil)
		s.findings.Store(5)
		h := &handler{s: s}

		res, err := h.OnInvokeTool(wire.InvokeToolParams{Name: statusToolName})
		require.NoError(t, err)
		assert.False(t, res.IsError)

		var rep statusReport
		require.NoError(t, json.Unmarshal(res.Result, &rep))
		assert.Equal(t, int64(5), rep.FindingsFiled)
		assert.NotEmpty(t, rep.Description)
	})

	t.Run("unknown_tool_is_error", func(t *testing.T) {
		h := &handler{s: newScanner(defaultConfig(), nil, nil)}
		res, err := h.OnInvokeTool(wire.InvokeToolParams{Name: "bogus"})
		require.NoError(t, err)
		assert.True(t, res.IsError)

		var payload map[string]string
		require.NoError(t, json.Unmarshal(res.Result, &payload))
		assert.Contains(t, payload["error"], "bogus")
	})
}
