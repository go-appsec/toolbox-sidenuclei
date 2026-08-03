package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-appsec/toolbox/sidecar/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// flowsResponse marshals a proxyPoll into the canned CoreInvokeResult content.
func flowsResponse(flows []flowEntry, remaining int) string {
	b, _ := json.Marshal(proxyPoll{Flows: flows, RemainingCount: remaining})
	return string(b)
}

// proxyFlow builds a proxy-source flow entry.
func proxyFlow(id, method, scheme, host string, port int, path string) flowEntry {
	return flowEntry{FlowID: id, Method: method, Scheme: scheme, Host: host, Port: port, Path: path, Source: "proxy"}
}

func TestEndpointKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		flow flowEntry
		want string
	}{
		{"basic", flowEntry{Method: "GET", Scheme: "https", Host: "example.com", Port: 443, Path: "/api/v1/users"}, "GET https://example.com:443/api/v1/users"},
		{"keeps_param_names", flowEntry{Method: "POST", Scheme: "http", Host: "x.com", Port: 8080, Path: "/search?q=a&q=b"}, "POST http://x.com:8080/search?q"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, endpointKey(tt.flow))
		})
	}

	t.Run("value_variation_same_key", func(t *testing.T) {
		f1 := flowEntry{Method: "GET", Scheme: "http", Host: "h", Port: 82, Path: "/p?x=1&y=2"}
		f2 := flowEntry{Method: "GET", Scheme: "http", Host: "h", Port: 82, Path: "/p?y=9&x=8"}
		assert.Equal(t, endpointKey(f1), endpointKey(f2))
	})

	t.Run("distinct_params_differ", func(t *testing.T) {
		f1 := flowEntry{Method: "GET", Scheme: "http", Host: "h", Port: 82, Path: "/p?a=1"}
		f2 := flowEntry{Method: "GET", Scheme: "http", Host: "h", Port: 82, Path: "/p?b=1"}
		assert.NotEqual(t, endpointKey(f1), endpointKey(f2))
	})
}

func TestSkip(t *testing.T) {
	t.Parallel()

	t.Run("replay_source", func(t *testing.T) {
		s := newScanner(Config{}, nil, nil)
		f := proxyFlow("f1", "GET", "http", "h", 80, "/p")
		f.Source = "replay"
		assert.True(t, s.skip(f))
	})

	t.Run("external_flow_scanned", func(t *testing.T) {
		s := newScanner(Config{}, nil, nil)
		f := proxyFlow("f1", "GET", "http", "ext.com", 80, "/api")
		assert.False(t, s.skip(f))
	})

	t.Run("dedup_same_endpoint", func(t *testing.T) {
		s := newScanner(Config{}, nil, nil)
		f1 := proxyFlow("f1", "GET", "http", "h", 82, "/p?x=1")
		f2 := proxyFlow("f2", "GET", "http", "h", 82, "/p?x=2")
		assert.False(t, s.skip(f1))
		assert.True(t, s.skip(f2))
	})

	t.Run("different_endpoints_scanned", func(t *testing.T) {
		s := newScanner(Config{}, nil, nil)
		f1 := proxyFlow("f1", "GET", "http", "h", 80, "/a")
		f2 := proxyFlow("f2", "POST", "http", "h", 0, "/b")
		assert.False(t, s.skip(f1))
		assert.False(t, s.skip(f2))
	})
}

func TestPoll(t *testing.T) {
	t.Parallel()

	t.Run("advances_on_success", func(t *testing.T) {
		flows := []flowEntry{
			proxyFlow("f1", "GET", "http", "h", 80, "/a"),
			proxyFlow("f2", "POST", "http", "h", 0, "/b"),
		}
		s := newScanner(Config{PollLimit: 10, Source: "proxy"}, func(_ context.Context, _ string, _ any) (wire.CoreInvokeResult, error) {
			return wire.CoreInvokeResult{Content: flowsResponse(flows, 3)}, nil
		}, nil)
		poll, ok := s.poll(t.Context(), "")
		require.True(t, ok)
		require.Len(t, poll.Flows, 2)
		assert.Equal(t, 3, poll.RemainingCount)
	})

	t.Run("false_on_core_error", func(t *testing.T) {
		s := newScanner(Config{PollLimit: 10}, func(_ context.Context, _ string, _ any) (wire.CoreInvokeResult, error) {
			return wire.CoreInvokeResult{}, assert.AnError
		}, nil)
		_, ok := s.poll(t.Context(), "cursor-42")
		assert.False(t, ok)
	})

	t.Run("false_on_tool_error", func(t *testing.T) {
		s := newScanner(Config{PollLimit: 10}, func(_ context.Context, _ string, _ any) (wire.CoreInvokeResult, error) {
			return wire.CoreInvokeResult{Content: `{"error":"boom"}`, IsError: true}, nil
		}, nil)
		_, ok := s.poll(t.Context(), "cursor-42")
		assert.False(t, ok)
	})

	t.Run("false_on_bad_json", func(t *testing.T) {
		s := newScanner(Config{PollLimit: 10}, func(_ context.Context, _ string, _ any) (wire.CoreInvokeResult, error) {
			return wire.CoreInvokeResult{Content: "not-json"}, nil
		}, nil)
		_, ok := s.poll(t.Context(), "cursor-42")
		assert.False(t, ok)
	})

	t.Run("passes_since_cursor", func(t *testing.T) {
		var received string
		s := newScanner(Config{PollLimit: 10}, func(_ context.Context, _ string, params any) (wire.CoreInvokeResult, error) {
			received = params.(map[string]any)["since"].(string)
			return wire.CoreInvokeResult{Content: `{"flows":[],"remaining_count":0}`}, nil
		}, nil)
		_, ok := s.poll(t.Context(), "my-cursor")
		require.True(t, ok)
		assert.Equal(t, "my-cursor", received)
	})
}

func TestSeedFromNow(t *testing.T) {
	t.Parallel()

	t.Run("newest_flow_id", func(t *testing.T) {
		flows := []flowEntry{
			proxyFlow("old", "GET", "http", "h", 80, "/a"),
			proxyFlow("new", "POST", "http", "h", 0, "/b"),
		}
		s := newScanner(Config{PollLimit: 10}, func(_ context.Context, _ string, _ any) (wire.CoreInvokeResult, error) {
			return wire.CoreInvokeResult{Content: flowsResponse(flows, 1)}, nil
		}, nil)
		assert.Equal(t, "new", s.seedFromNow(t.Context()))
	})

	t.Run("empty_when_no_flows", func(t *testing.T) {
		s := newScanner(Config{PollLimit: 10}, func(_ context.Context, _ string, _ any) (wire.CoreInvokeResult, error) {
			return wire.CoreInvokeResult{Content: `{"flows":[],"remaining_count":0}`}, nil
		}, nil)
		assert.Empty(t, s.seedFromNow(t.Context()))
	})

	t.Run("empty_on_failure", func(t *testing.T) {
		s := newScanner(Config{PollLimit: 10}, func(_ context.Context, _ string, _ any) (wire.CoreInvokeResult, error) {
			return wire.CoreInvokeResult{}, assert.AnError
		}, nil)
		assert.Empty(t, s.seedFromNow(t.Context()))
	})
}

func TestRemainingCountBackoff(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		remaining int
		interval  time.Duration
		want      time.Duration
	}{
		{"zero_remaining_waits", 0, 1500 * time.Millisecond, 1500 * time.Millisecond},
		{"positive_no_wait", 5, time.Second, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, remainingCountBackoff(tt.remaining, tt.interval))
		})
	}
}
