package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-appsec/toolbox-sidenuclei/sidenuclei/nuclei"
)

// findingContent renders a greppable note body: a severity-prefixed header plus
// the fuzz parameter, classification, OOB proof, extracted evidence, curl
// reproducer, and description when present.
func findingContent(f nuclei.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[nuclei:%s] %s", f.Severity, f.TemplateID)
	if f.Name != "" {
		fmt.Fprintf(&b, " (%s)", f.Name)
	}
	if f.MatchedAt != "" {
		b.WriteString(" ")
		b.WriteString(f.MatchedAt)
	}

	var fuzz, oob string
	if f.IsFuzzingResult {
		fuzz = strings.TrimSpace(f.FuzzingMethod + " " + f.FuzzingParameter + " @" + f.FuzzingPosition)
	}
	if f.InteractionProtocol != "" {
		oob = strings.TrimSpace(f.InteractionProtocol + " " + f.InteractionRemote)
	}
	for _, line := range []struct{ label, value string }{
		{"fuzz", fuzz},
		{"class", classification(f)},
		{"oob", oob},
		{"extracted", strings.Join(f.ExtractedResults, ", ")},
		{"curl", f.CURLCommand},
	} {
		if line.value != "" {
			fmt.Fprintf(&b, "\n%s: %s", line.label, line.value)
		}
	}
	if desc := strings.TrimSpace(f.Description); desc != "" {
		b.WriteByte('\n')
		b.WriteString(desc)
	}
	return b.String()
}

// classification renders the cve/cwe/cvss line, empty when none are set.
func classification(f nuclei.Finding) string {
	var parts []string
	if f.CVEID != "" {
		parts = append(parts, "cve="+f.CVEID)
	}
	if f.CWEID != "" {
		parts = append(parts, "cwe="+f.CWEID)
	}
	if f.CVSSScore > 0 {
		parts = append(parts, "cvss="+strconv.FormatFloat(f.CVSSScore, 'f', -1, 64))
	}
	return strings.Join(parts, " ")
}

// noteParams builds the notes_save params for one finding. flow_ids must be a
// JSON array encoded as a STRING; the tool schema reads it via GetString and
// parses it itself, so a raw slice would not round-trip.
func noteParams(flowID string, f nuclei.Finding) map[string]any {
	return map[string]any{
		"type":     "finding",
		"flow_ids": flowIDsJSON([]string{flowID}),
		"content":  findingContent(f),
	}
}

// flowIDsJSON marshals ids into a JSON array string for the notes tools.
func flowIDsJSON(ids []string) string {
	b, err := json.Marshal(ids)
	if err != nil {
		return "[]" // unreachable for []string; keep the note valid
	}
	return string(b)
}

// alreadyFiled reports whether a finding with the same template and matched-at was
// already filed (e.g. matched by both passes), recording it as filed otherwise.
func (s *scanner) alreadyFiled(f nuclei.Finding) bool {
	key := f.TemplateID + "\x00" + f.MatchedAt
	s.filedMu.Lock()
	defer s.filedMu.Unlock()
	if _, ok := s.filed[key]; ok {
		return true
	}
	s.filed[key] = struct{}{}
	return false
}

// saveFinding files one finding as a note linked to the originating flow, skipping
// duplicates. When sectool runs without --notes (IsError), it warns once and continues.
func (s *scanner) saveFinding(ctx context.Context, flowID string, f nuclei.Finding) {
	if s.alreadyFiled(f) {
		return
	}
	res, err := s.invoke(ctx, "notes_save", noteParams(flowID, f))
	if err != nil {
		s.logf(logWarn, "save finding failed", map[string]any{
			flowIDField: flowID,
			errField:    err.Error(),
		})
		return
	}
	if res.IsError {
		if s.notesWarned.CompareAndSwap(false, true) {
			s.logf(logWarn, "notes_save unavailable - sectool running without --notes; findings not filed",
				map[string]any{flowIDField: flowID})
		}
		return
	}
	s.findings.Add(1)
}
