package nuclei

import (
	"encoding/base64"
	"strconv"
	"strings"

	"github.com/go-analyze/bulk"
)

// FlowRequest is the request side of a captured flow, as returned by flow_get with
// scope:"request_headers,request_body". Headers carries the request-line + header
// block; Body is base64-encoded (empty when there is no body).
type FlowRequest struct {
	URL     string
	Headers string
	Body    string
}

// BuildImportTarget assembles a full-request ImportTarget from a captured flow.
// It normalizes line endings to CRLF, decodes the body, and fixes framing headers
// (drops Transfer-Encoding, sets Content-Length to the real body length). Reports
// false when the request is unusable: empty header block, undecodable body, or a
// raw request exceeding maxBytes.
func BuildImportTarget(req FlowRequest, maxBytes int) (ImportTarget, bool) {
	head := strings.TrimRight(req.Headers, "\r\n")
	if head == "" {
		return ImportTarget{}, false
	}

	var body []byte
	if req.Body != "" {
		b, err := base64.StdEncoding.DecodeString(req.Body)
		if err != nil {
			return ImportTarget{}, false
		}
		body = b
	}

	head = rewriteFraming(head, len(body))

	var b strings.Builder
	b.WriteString(strings.ReplaceAll(head, "\n", "\r\n"))
	b.WriteString("\r\n\r\n")
	b.Write(body)

	if maxBytes > 0 && b.Len() > maxBytes {
		return ImportTarget{}, false
	}
	return ImportTarget{URL: req.URL, Raw: b.String()}, true
}

// rewriteFraming drops chunked Transfer-Encoding and, when a body is present,
// replaces Content-Length with bodyLen so the assembled raw request is self-consistent.
func rewriteFraming(head string, bodyLen int) string {
	lines := bulk.SliceFilterInPlace(func(l string) bool {
		key := strings.ToLower(strings.TrimSpace(l))
		if strings.HasPrefix(key, "transfer-encoding:") {
			return false
		}
		return bodyLen == 0 || !strings.HasPrefix(key, "content-length:") // drop; replaced below
	}, strings.Split(head, "\n"))
	if bodyLen > 0 {
		lines = append(lines, "Content-Length: "+strconv.Itoa(bodyLen))
	}
	return strings.Join(lines, "\n")
}
