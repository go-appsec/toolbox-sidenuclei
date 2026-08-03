package main

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/go-appsec/toolbox-sidenuclei/sidenuclei/nuclei"
)

// scanEngine runs the enabled nuclei passes over targets, invoking cb per finding.
type scanEngine interface {
	Scan(ctx context.Context, targets []nuclei.ImportTarget, cb func(nuclei.Finding)) error
	Close() error
}

// flowRequestDetail mirrors the request-side fields of a flow_get response.
type flowRequestDetail struct {
	URL        string `json:"url"`
	ReqHeaders string `json:"request_headers"`
	ReqBody    string `json:"request_body"`
}

// startWorkers launches n scan workers that drain the queue until it closes.
func (s *scanner) startWorkers(ctx context.Context, n int) {
	if n < 1 {
		n = 1
	}
	for range n {
		go func() {
			for {
				j, ok := s.dequeue()
				if !ok {
					return
				}
				s.runScan(ctx, j)
			}
		}()
	}
}

// runScan scans the built target under the per-endpoint timeout and files each finding.
func (s *scanner) runScan(parent context.Context, j scanJob) {
	scanCtx, cancel := context.WithTimeout(parent, s.cfg.scanTimeout)
	defer cancel()

	s.endpointsScanned.Add(1)

	// file under parent, not scanCtx: a scan-deadline hit must not cancel notes_save
	err := s.engine.Scan(scanCtx, []nuclei.ImportTarget{j.target}, func(fd nuclei.Finding) {
		s.saveFinding(parent, j.flowID, fd)
	})
	if err != nil {
		s.logf(logWarn, "scan failed", map[string]any{
			flowIDField: j.flowID,
			targetField: j.target.URL,
			errField:    err.Error(),
		})
	}
}

// buildTarget builds the scan target for f from its full request. Reports false
// when the request can't be fetched or is unscannable.
func (s *scanner) buildTarget(ctx context.Context, f flowEntry) (nuclei.ImportTarget, bool) {
	res, err := s.invoke(ctx, "flow_get", map[string]any{
		"flow_id":   f.FlowID,
		"scope":     "request_headers,request_body",
		"full_body": true, // request_body must be base64, not a preview, for BuildImportTarget to decode
	})
	if err != nil || res.IsError {
		s.logf(logWarn, "skip: flow_get failed", map[string]any{flowIDField: f.FlowID})
		return nuclei.ImportTarget{}, false
	}

	var d flowRequestDetail
	if err := json.Unmarshal([]byte(res.Content), &d); err != nil {
		s.logf(logWarn, "skip: flow_get decode", map[string]any{flowIDField: f.FlowID, errField: err.Error()})
		return nuclei.ImportTarget{}, false
	}

	it, ok := nuclei.BuildImportTarget(nuclei.FlowRequest{
		URL:     d.URL,
		Headers: d.ReqHeaders,
		Body:    d.ReqBody,
	}, s.cfg.MaxRawRequestBytes)
	if !ok {
		s.logf(logWarn, "skip: unscannable request", map[string]any{flowIDField: f.FlowID})
		return nuclei.ImportTarget{}, false
	}

	_, it.Fuzzable = s.cfg.fuzzMethods[strings.ToUpper(f.Method)]
	return it, true
}
