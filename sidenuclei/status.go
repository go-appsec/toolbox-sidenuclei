package main

import (
	"encoding/json"
	"strings"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

// statusToolName is the MCP tool the agent polls for live scan status.
const statusToolName = "nuclei_status"

// statusReport is the structured projection returned by the nuclei_status tool.
type statusReport struct {
	Description      string       `json:"description"`
	Scanning         bool         `json:"scanning"`
	ActiveScans      int64        `json:"active_scans"`
	QueueDepth       int          `json:"queue_depth"`
	FlowsObserved    int64        `json:"flows_observed"`
	EndpointsScanned int64        `json:"endpoints_scanned"`
	Skipped          int64        `json:"skipped"`
	FindingsFiled    int64        `json:"findings_filed"`
	NotesFilingOK    bool         `json:"notes_filing_ok"`
	Coverage         coverageInfo `json:"coverage"`
}

// coverageInfo lists the enabled scan categories by name.
type coverageInfo struct {
	Detection        []string `json:"detection"`
	Fuzzing          []string `json:"fuzzing"`
	InjectionClasses []string `json:"injection_classes"`
}

// status snapshots the scanner's live counters and enabled coverage.
func (s *scanner) status() statusReport {
	cov := coverageInfo{
		Detection:        s.cfg.enabledDetectionNames(),
		Fuzzing:          s.cfg.enabledFuzzNames(),
		InjectionClasses: s.cfg.enabledInjectionClasses(),
	}
	active := s.inFlight.Load()
	queue := s.queueDepth()
	notesOK := !s.notesWarned.Load()
	return statusReport{
		Description:      statusDescription(cov, notesOK),
		Scanning:         active > 0 || queue > 0,
		ActiveScans:      active,
		QueueDepth:       queue,
		FlowsObserved:    s.flowsObserved.Load(),
		EndpointsScanned: s.endpointsScanned.Load(),
		Skipped:          s.skipped.Load(),
		FindingsFiled:    s.findings.Load(),
		NotesFilingOK:    notesOK,
		Coverage:         cov,
	}
}

// statusDescription renders a one-line summary of what is being scanned and where
// results land, plus a warning when notes filing is failing.
func statusDescription(cov coverageInfo, notesOK bool) string {
	var b strings.Builder
	b.WriteString("Passively scanning proxied endpoints with Nuclei")
	if len(cov.Detection) > 0 {
		b.WriteString("; detection: " + strings.Join(cov.Detection, ", "))
	}
	if len(cov.Fuzzing) > 0 {
		b.WriteString("; fuzzing: " + strings.Join(cov.Fuzzing, ", "))
	}
	b.WriteString(". Findings are filed to sectool notes (type=finding) linked to the originating flow; check notes for scan results")
	if !notesOK {
		b.WriteString(" (warning: notes_save is failing - sectool may be running without --notes, so findings are not being filed)")
	}
	return b.String() + "."
}

// OnInvokeTool serves the nuclei_status tool from live scanner state. Only the
// registered status tool is handled; any other name is a tool-level error. The
// result is the status JSON; sectool derives the client text fallback from it.
func (h *handler) OnInvokeTool(p wire.InvokeToolParams) (wire.InvokeToolResult, error) {
	if p.Name != statusToolName {
		return toolError("unknown tool: " + p.Name), nil
	}
	body, err := json.Marshal(h.s.status())
	if err != nil {
		return toolError("status marshal failed"), nil
	}
	return wire.InvokeToolResult{Result: body}, nil
}

// toolError renders msg as a structured error result matching the object output schema.
func toolError(msg string) wire.InvokeToolResult {
	body, _ := json.Marshal(map[string]string{"error": msg})
	return wire.InvokeToolResult{Result: body, IsError: true}
}
