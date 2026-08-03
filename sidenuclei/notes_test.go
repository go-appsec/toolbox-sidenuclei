package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-appsec/toolbox-sidenuclei/sidenuclei/nuclei"
	"github.com/go-appsec/toolbox/sidecar/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNoteParams(t *testing.T) {
	t.Parallel()

	t.Run("encodes_flow_ids_as_json_string", func(t *testing.T) {
		p := noteParams("flow-123", nuclei.Finding{TemplateID: "CVE-X", MatchedAt: "/api"})

		v, ok := p["flow_ids"].(string)
		require.True(t, ok)
		var ids []string
		require.NoError(t, json.Unmarshal([]byte(v), &ids))
		assert.Equal(t, []string{"flow-123"}, ids)
		assert.Equal(t, "finding", p["type"])
	})

	t.Run("header_and_description", func(t *testing.T) {
		f := nuclei.Finding{TemplateID: "CVE-X", MatchedAt: "https://example.com/", Name: "XSS", Severity: "high", Description: "Reflected input"}
		assert.Equal(t, "[nuclei:high] CVE-X (XSS) https://example.com/\nReflected input", findingContent(f))
	})

	t.Run("omits_empty_name_and_description", func(t *testing.T) {
		assert.Equal(t, "[nuclei:] T1 /", findingContent(nuclei.Finding{TemplateID: "T1", MatchedAt: "/"}))
	})

	t.Run("renders_fuzz_class_oob_extracted_curl", func(t *testing.T) {
		f := nuclei.Finding{
			TemplateID: "T", Severity: "critical", MatchedAt: "http://h/x",
			IsFuzzingResult: true, FuzzingMethod: "GET", FuzzingParameter: "id", FuzzingPosition: "query",
			CVEID: "CVE-1", CWEID: "CWE-89", CVSSScore: 9.8,
			InteractionProtocol: "dns", InteractionRemote: "1.2.3.4",
			ExtractedResults: []string{"root:x"}, CURLCommand: "curl http://h/x",
		}
		got := findingContent(f)
		assert.Contains(t, got, "\nfuzz: GET id @query")
		assert.Contains(t, got, "\nclass: cve=CVE-1 cwe=CWE-89 cvss=9.8")
		assert.Contains(t, got, "\noob: dns 1.2.3.4")
		assert.Contains(t, got, "\nextracted: root:x")
		assert.Contains(t, got, "\ncurl: curl http://h/x")
	})
}

func TestFlowIDsJSON(t *testing.T) {
	t.Parallel()

	assert.Equal(t, `["a","b"]`, flowIDsJSON([]string{"a", "b"}))
}

func TestSaveFinding(t *testing.T) {
	t.Parallel()

	t.Run("files_note_and_counts", func(t *testing.T) {
		var gotTool string
		var gotParams map[string]any
		invoke := func(_ context.Context, tool string, params any) (wire.CoreInvokeResult, error) {
			gotTool = tool
			gotParams, _ = params.(map[string]any)
			return wire.CoreInvokeResult{Content: `{"note_id":"n1"}`}, nil
		}

		s := newScanner(Config{}, invoke, nil)
		f := nuclei.Finding{TemplateID: "CVE-X", MatchedAt: "/api", Severity: "medium"}
		s.saveFinding(t.Context(), "flow-123", f)

		assert.Equal(t, "notes_save", gotTool)
		assert.NotNil(t, gotParams)
		assert.Equal(t, int64(1), s.findings.Load())
	})

	t.Run("dedup_same_template_and_location", func(t *testing.T) {
		var calls int
		invoke := func(_ context.Context, _ string, _ any) (wire.CoreInvokeResult, error) {
			calls++
			return wire.CoreInvokeResult{Content: `{"note_id":"n"}`}, nil
		}
		s := newScanner(Config{}, invoke, nil)
		f := nuclei.Finding{TemplateID: "T1", MatchedAt: "http://h/x"}
		s.saveFinding(t.Context(), "flow-a", f)
		s.saveFinding(t.Context(), "flow-b", f)
		assert.Equal(t, 1, calls)
		assert.Equal(t, int64(1), s.findings.Load())
	})

	t.Run("not_counted_when_notes_disabled", func(t *testing.T) {
		invoke := func(_ context.Context, _ string, _ any) (wire.CoreInvokeResult, error) {
			return wire.CoreInvokeResult{Content: `{"error":"notes disabled"}`, IsError: true}, nil
		}

		s := newScanner(Config{}, invoke, nil)
		s.saveFinding(t.Context(), "f", nuclei.Finding{TemplateID: "T1", MatchedAt: "/"})

		assert.Zero(t, s.findings.Load())
		assert.True(t, s.notesWarned.Load())
	})

	t.Run("warns_once_when_notes_disabled", func(t *testing.T) {
		var warnings int
		invoke := func(_ context.Context, _ string, _ any) (wire.CoreInvokeResult, error) {
			return wire.CoreInvokeResult{Content: `{"error":"notes disabled"}`, IsError: true}, nil
		}

		s := newScanner(Config{}, invoke, nil)
		s.logf = func(level, message string, _ map[string]any) {
			if level == logWarn && strings.Contains(message, "--notes") {
				warnings++
			}
		}

		s.saveFinding(t.Context(), "f", nuclei.Finding{TemplateID: "T1", MatchedAt: "/a"})
		s.saveFinding(t.Context(), "g", nuclei.Finding{TemplateID: "T2", MatchedAt: "/b"})

		assert.Equal(t, 1, warnings)
	})

	t.Run("invoke_error_not_counted", func(t *testing.T) {
		invoke := func(_ context.Context, _ string, _ any) (wire.CoreInvokeResult, error) {
			return wire.CoreInvokeResult{}, assert.AnError
		}

		s := newScanner(Config{}, invoke, nil)
		s.saveFinding(t.Context(), "f", nuclei.Finding{TemplateID: "T1", MatchedAt: "/"})

		assert.Zero(t, s.findings.Load())
	})
}
