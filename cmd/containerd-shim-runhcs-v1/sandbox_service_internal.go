//go:build windows

package main

import (
	"context"

	"github.com/containerd/containerd/api/runtime/sandbox/v1"
)

func (s *service) createSandbox(ctx context.Context, request *sandbox.CreateSandboxRequest) (*sandbox.CreateSandboxResponse, error) {
	return nil, nil
}

func (s *service) startSandbox(ctx context.Context, request *sandbox.StartSandboxRequest) (*sandbox.StartSandboxResponse, error) {
	return nil, nil
}

func (s *service) platform(ctx context.Context, request *sandbox.PlatformRequest) (*sandbox.PlatformResponse, error) {
	return nil, nil
}

func (s *service) stopSandbox(ctx context.Context, request *sandbox.StopSandboxRequest) (*sandbox.StopSandboxResponse, error) {
	return nil, nil
}

func (s *service) waitSandbox(ctx context.Context, request *sandbox.WaitSandboxRequest) (*sandbox.WaitSandboxResponse, error) {
	return nil, nil
}

func (s *service) sandboxStatus(ctx context.Context, request *sandbox.SandboxStatusRequest) (*sandbox.SandboxStatusResponse, error) {
	return nil, nil
}

func (s *service) pingSandbox(ctx context.Context, request *sandbox.PingRequest) (*sandbox.PingResponse, error) {
	return nil, nil
}

func (s *service) shutdownSandbox(ctx context.Context, request *sandbox.ShutdownSandboxRequest) (*sandbox.ShutdownSandboxResponse, error) {
	return nil, nil
}

func (s *service) sandboxMetrics(ctx context.Context, request *sandbox.SandboxMetricsRequest) (*sandbox.SandboxMetricsResponse, error) {
	return nil, nil
}
