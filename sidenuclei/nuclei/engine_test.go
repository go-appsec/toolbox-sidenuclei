package nuclei

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteTargets(t *testing.T) {
	t.Parallel()

	t.Run("encodes_url_and_raw", func(t *testing.T) {
		e := &Engine{dir: t.TempDir()}
		path, err := e.writeTargets([]ImportTarget{{URL: "http://h/p", Raw: "GET /p HTTP/1.1\r\nHost: h\r\n\r\n"}})
		require.NoError(t, err)

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		var doc proxifyDoc
		require.NoError(t, json.Unmarshal(data, &doc))
		assert.Equal(t, "http://h/p", doc.URL)
		assert.Equal(t, "GET /p HTTP/1.1\r\nHost: h\r\n\r\n", doc.Request.Raw)
		assert.Equal(t, "http://h/p", doc.Request.Endpoint)
	})

	t.Run("unique_path_per_call", func(t *testing.T) {
		e := &Engine{dir: t.TempDir()}
		p1, err := e.writeTargets(nil)
		require.NoError(t, err)
		p2, err := e.writeTargets(nil)
		require.NoError(t, err)
		assert.NotEqual(t, p1, p2)
	})
}
