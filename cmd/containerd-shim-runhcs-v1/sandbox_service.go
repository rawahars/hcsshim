//go:build windows

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/sandbox_options"
	"github.com/Microsoft/hcsshim/internal/oc"

	"github.com/containerd/containerd/api/runtime/sandbox/v1"
	errdefs "github.com/containerd/errdefs/pkg/errgrpc"
	"go.opencensus.io/trace"
)

var _ sandbox.TTRPCSandboxService = &service{}

// CreateSandbox creates (or prepares) a new sandbox for the given SandboxID.
func (s *service) CreateSandbox(ctx context.Context, request *sandbox.CreateSandboxRequest) (resp *sandbox.CreateSandboxResponse, err error) {
	ctx, span := oc.StartSpan(ctx, "CreateSandbox")
	defer span.End()
	defer func() {
		oc.SetSpanStatus(span, err)
	}()

	span.AddAttributes(
		trace.StringAttribute("sandbox-id", request.SandboxID),
		trace.StringAttribute("bundle", request.BundlePath),
		trace.StringAttribute("net-ns-path", request.NetnsPath))

	// Decode the Sandbox spec passed along from CRI.
	var sandboxSpec sandbox_options.SandboxSpec
	f, err := os.Open(filepath.Join(request.BundlePath, "config.json"))
	if err != nil {
		return nil, err
	}
	if err := json.NewDecoder(f).Decode(&sandboxSpec); err != nil {
		f.Close()
		return nil, err
	}
	f.Close()

	r, e := s.createSandbox(ctx, request.SandboxID, request.Rootfs, request.BundlePath, &sandboxSpec)
	return r, errdefs.ToGRPC(e)
}

// StartSandbox transitions a previously created sandbox to the "running" state.
func (s *service) StartSandbox(ctx context.Context, request *sandbox.StartSandboxRequest) (resp *sandbox.StartSandboxResponse, err error) {
	ctx, span := oc.StartSpan(ctx, "StartSandbox")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	span.AddAttributes(trace.StringAttribute("sandbox-id", request.SandboxID))

	r, e := s.startSandbox(ctx, request.SandboxID)
	return r, errdefs.ToGRPC(e)
}

// Platform returns the platform details for the sandbox ("windows/amd64" or "linux/amd64").
func (s *service) Platform(ctx context.Context, request *sandbox.PlatformRequest) (resp *sandbox.PlatformResponse, err error) {
	ctx, span := oc.StartSpan(ctx, "Platform")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	span.AddAttributes(trace.StringAttribute("sandbox-id", request.SandboxID))

	r, e := s.platform(ctx, request.SandboxID)
	return r, errdefs.ToGRPC(e)
}

// StopSandbox attempts a graceful stop of the sandbox within the specified timeout.
func (s *service) StopSandbox(ctx context.Context, request *sandbox.StopSandboxRequest) (resp *sandbox.StopSandboxResponse, err error) {
	ctx, span := oc.StartSpan(ctx, "StopSandbox")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	span.AddAttributes(trace.StringAttribute("sandbox-id", request.SandboxID))
	span.AddAttributes(trace.Int64Attribute("timeout-secs", int64(request.TimeoutSecs)))

	r, e := s.stopSandbox(ctx, request)
	return r, errdefs.ToGRPC(e)
}

// WaitSandbox blocks until the sandbox reaches a terminal state (stopped/errored) and returns the outcome.
func (s *service) WaitSandbox(ctx context.Context, request *sandbox.WaitSandboxRequest) (resp *sandbox.WaitSandboxResponse, err error) {
	ctx, span := oc.StartSpan(ctx, "WaitSandbox")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	span.AddAttributes(trace.StringAttribute("sandbox-id", request.SandboxID))

	r, e := s.waitSandbox(ctx, request)
	return r, errdefs.ToGRPC(e)
}

// SandboxStatus returns current status for the sandbox, optionally verbose.
func (s *service) SandboxStatus(ctx context.Context, request *sandbox.SandboxStatusRequest) (resp *sandbox.SandboxStatusResponse, err error) {
	ctx, span := oc.StartSpan(ctx, "SandboxStatus")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	span.AddAttributes(trace.StringAttribute("sandbox-id", request.SandboxID))
	span.AddAttributes(trace.BoolAttribute("verbose", request.Verbose))

	r, e := s.sandboxStatus(ctx, request)
	return r, errdefs.ToGRPC(e)
}

// PingSandbox performs a minimal liveness check on the sandbox and returns quickly.
func (s *service) PingSandbox(ctx context.Context, request *sandbox.PingRequest) (resp *sandbox.PingResponse, err error) {
	ctx, span := oc.StartSpan(ctx, "PingSandbox")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	span.AddAttributes(trace.StringAttribute("sandbox-id", request.SandboxID))

	r, e := s.pingSandbox(ctx, request)
	return r, errdefs.ToGRPC(e)
}

// ShutdownSandbox requests a full shim + sandbox shutdown (stronger than StopSandbox),
// typically used by the higher-level controller to tear down resources and exit the shim.
func (s *service) ShutdownSandbox(ctx context.Context, request *sandbox.ShutdownSandboxRequest) (resp *sandbox.ShutdownSandboxResponse, err error) {
	ctx, span := oc.StartSpan(ctx, "ShutdownSandbox")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	span.AddAttributes(trace.StringAttribute("sandbox-id", request.SandboxID))

	r, e := s.shutdownSandbox(ctx, request)
	return r, errdefs.ToGRPC(e)
}

// SandboxMetrics returns runtime metrics for the sandbox (e.g., CPU/memory/IO),
// suitable for monitoring and autoscaling decisions.
func (s *service) SandboxMetrics(ctx context.Context, request *sandbox.SandboxMetricsRequest) (resp *sandbox.SandboxMetricsResponse, err error) {
	ctx, span := oc.StartSpan(ctx, "SandboxMetrics")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	span.AddAttributes(trace.StringAttribute("sandbox-id", request.SandboxID))

	r, e := s.sandboxMetrics(ctx, request)
	return r, errdefs.ToGRPC(e)
}
