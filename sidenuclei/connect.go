package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-appsec/toolbox/sidecar"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// dialTimeout bounds the connect + register handshake.
const dialTimeout = 10 * time.Second

// statusTool is the read-only MCP tool the sidecar exposes so agents can poll live
// scan status. Findings themselves are filed to notes, not returned here.
var statusTool = wire.MCPTool{
	Name:        statusToolName,
	Description: "Proxy flows are automatically scanned by Nuclei. This tool reports the scan status: activity, queue depth, findings filed, and enabled coverage. Findings are filed to sectool notes (type=finding) linked to the originating flow - check notes for the actual scan results. Check this status and the notes when you are reaching the end of a testing strategy and want to explore possible pivots, or to catch results you may have missed.",
	InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
}

// connect dials sectool at cfg.Socket and registers the read-only status tool. The
// sidecar claims no connections and originates no flows.
func connect(ctx context.Context, cfg Config) (*sidecar.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	conn, err := sidecar.Dial(ctx, cfg.Socket, sidecar.Registration{
		Name:      "nuclei-scanner",
		Protocols: nil, // observes only; originates nothing
		MCPTools:  []wire.MCPTool{statusTool},
	})
	if errors.Is(err, sidecar.ErrVersionUnsupported) {
		return nil, errors.New("protocol version unsupported - rebuild against the running sectool")
	} else if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	return conn, nil
}
