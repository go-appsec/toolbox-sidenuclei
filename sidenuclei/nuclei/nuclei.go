package nuclei

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// ImportTarget is one full-request scan target: an absolute URL plus the raw HTTP
// request bytes (request-line + headers + CRLFCRLF + body) nuclei fuzzes. Fuzzable
// gates the active DAST pass (set by the caller's method policy); detection always runs.
type ImportTarget struct {
	URL      string
	Raw      string
	Fuzzable bool
}

// Finding is a trimmed projection of nuclei's output.ResultEvent carrying only the
// fields we file. Pass is "detect" or "fuzz" (the engine that produced it).
type Finding struct {
	Pass             string
	TemplateID       string
	Name             string
	Severity         string
	Description      string
	MatchedAt        string
	Host             string
	URL              string
	CURLCommand      string
	ExtractedResults []string
	CVEID            string
	CWEID            string
	CVSSScore        float64
	Tags             []string

	IsFuzzingResult  bool
	FuzzingMethod    string
	FuzzingParameter string
	FuzzingPosition  string

	InteractionProtocol string
	InteractionRemote   string
}

// mapEvent projects a nuclei result event into a Finding, flattening the nested
// info/classification and OOB interaction. pass tags the originating engine.
func mapEvent(pass string, ev *output.ResultEvent) Finding {
	f := Finding{
		Pass:             pass,
		TemplateID:       ev.TemplateID,
		Name:             ev.Info.Name,
		Severity:         ev.Info.SeverityHolder.Severity.String(),
		Description:      ev.Info.Description,
		MatchedAt:        ev.Matched,
		Host:             ev.Host,
		URL:              ev.URL,
		CURLCommand:      ev.CURLCommand,
		ExtractedResults: ev.ExtractedResults,
		Tags:             ev.Info.Tags.ToSlice(),
		IsFuzzingResult:  ev.IsFuzzingResult,
		FuzzingMethod:    ev.FuzzingMethod,
		FuzzingParameter: ev.FuzzingParameter,
		FuzzingPosition:  ev.FuzzingPosition,
	}
	if c := ev.Info.Classification; c != nil {
		f.CVEID = c.CVEID.String()
		f.CWEID = c.CWEID.String()
		f.CVSSScore = c.CVSSScore
	}
	if i := ev.Interaction; i != nil {
		f.InteractionProtocol = i.Protocol
		f.InteractionRemote = i.RemoteAddress
	}
	return f
}
