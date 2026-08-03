package nuclei

import (
	"testing"

	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/assert"
)

func TestMapEvent(t *testing.T) {
	t.Parallel()

	t.Run("full_event", func(t *testing.T) {
		ev := &output.ResultEvent{
			TemplateID: "T", Matched: "http://h/x", Host: "h", URL: "http://h",
			CURLCommand: "curl http://h/x", ExtractedResults: []string{"root:x"},
			MatcherStatus: true, IsFuzzingResult: true,
			FuzzingMethod: "GET", FuzzingParameter: "id", FuzzingPosition: "query",
			Info: model.Info{
				Name: "N", Description: "D",
				SeverityHolder: severity.Holder{Severity: severity.High},
				Tags:           stringslice.New([]string{"xss", "dast"}),
				Classification: &model.Classification{
					CVEID: stringslice.New("CVE-1"), CWEID: stringslice.New("CWE-89"), CVSSScore: 9.8,
				},
			},
			Interaction: &server.Interaction{Protocol: "dns", RemoteAddress: "1.2.3.4"},
		}
		f := mapEvent("fuzz", ev)

		assert.Equal(t, "fuzz", f.Pass)
		assert.Equal(t, "T", f.TemplateID)
		assert.Equal(t, "high", f.Severity)
		assert.Equal(t, "http://h/x", f.MatchedAt)
		assert.Equal(t, "id", f.FuzzingParameter)
		assert.Equal(t, "CVE-1", f.CVEID)
		assert.Equal(t, "CWE-89", f.CWEID)
		assert.InEpsilon(t, 9.8, f.CVSSScore, 1e-9)
		assert.Equal(t, []string{"xss", "dast"}, f.Tags)
		assert.Equal(t, "dns", f.InteractionProtocol)
		assert.Equal(t, "1.2.3.4", f.InteractionRemote)
	})

	t.Run("nil_classification_and_interaction", func(t *testing.T) {
		f := mapEvent("detect", &output.ResultEvent{TemplateID: "B"})
		assert.Empty(t, f.CVEID)
		assert.Empty(t, f.InteractionProtocol)
		assert.Empty(t, f.Tags)
	})
}
