package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-appsec/toolbox/sidecar"
)

// dialTimeout bounds the connect + register handshake.
const dialTimeout = 10 * time.Second

// connect dials sectool at cfg.Socket and registers with no capabilities.
func connect(ctx context.Context, cfg Config) (*sidecar.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	reg := sidecar.Registration{
		Name:       "nuclei-scanner",
		Protocols:  nil, // observes only; originates nothing
		InstanceID: cfg.InstanceID,
	}

	conn, err := sidecar.Dial(ctx, cfg.Socket, reg)
	if errors.Is(err, sidecar.ErrVersionUnsupported) {
		return nil, errors.New("protocol version unsupported - rebuild against the running sectool")
	}
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}

	return conn, nil
}
