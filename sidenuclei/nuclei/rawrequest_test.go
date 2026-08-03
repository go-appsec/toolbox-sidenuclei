package nuclei

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestBuildImportTarget(t *testing.T) {
	t.Parallel()

	t.Run("get_no_body", func(t *testing.T) {
		it, ok := BuildImportTarget(FlowRequest{
			URL:     "http://h/p?x=1",
			Headers: "GET /p?x=1 HTTP/1.1\nHost: h",
		}, 1<<20)
		require.True(t, ok)
		assert.Equal(t, "http://h/p?x=1", it.URL)
		assert.Equal(t, "GET /p?x=1 HTTP/1.1\r\nHost: h\r\n\r\n", it.Raw)
	})

	t.Run("post_body_sets_content_length", func(t *testing.T) {
		it, ok := BuildImportTarget(FlowRequest{
			URL:     "http://h/p",
			Headers: "POST /p HTTP/1.1\nHost: h\nContent-Length: 999",
			Body:    b64("a=1&b=2"),
		}, 1<<20)
		require.True(t, ok)
		assert.Contains(t, it.Raw, "Content-Length: 7")
		assert.NotContains(t, it.Raw, "Content-Length: 999")
		assert.True(t, strings.HasSuffix(it.Raw, "\r\n\r\na=1&b=2"))
	})

	t.Run("empty_headers_skipped", func(t *testing.T) {
		_, ok := BuildImportTarget(FlowRequest{URL: "http://h/", Headers: ""}, 1<<20)
		assert.False(t, ok)
	})

	t.Run("bad_base64_skipped", func(t *testing.T) {
		_, ok := BuildImportTarget(FlowRequest{URL: "http://h/", Headers: "GET / HTTP/1.1", Body: "!!!"}, 1<<20)
		assert.False(t, ok)
	})

	t.Run("oversized_skipped", func(t *testing.T) {
		_, ok := BuildImportTarget(FlowRequest{URL: "http://h/", Headers: "GET / HTTP/1.1\nHost: h", Body: b64(strings.Repeat("x", 100))}, 64)
		assert.False(t, ok)
	})
}

func TestRewriteFraming(t *testing.T) {
	t.Parallel()

	t.Run("drops_chunked_and_sets_length", func(t *testing.T) {
		got := rewriteFraming("POST /p HTTP/1.1\nHost: h\nTransfer-Encoding: chunked", 5)
		assert.NotContains(t, got, "Transfer-Encoding")
		assert.Contains(t, got, "Content-Length: 5")
	})

	t.Run("no_body_keeps_content_length", func(t *testing.T) {
		got := rewriteFraming("GET /p HTTP/1.1\nHost: h\nContent-Length: 0", 0)
		assert.Contains(t, got, "Content-Length: 0")
	})
}
