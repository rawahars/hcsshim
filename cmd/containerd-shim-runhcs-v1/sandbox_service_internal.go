//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/sandbox_options"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/uvm"
	"github.com/Microsoft/hcsshim/osversion"
	"github.com/containerd/containerd/api/runtime/sandbox/v1"
	"github.com/containerd/containerd/api/types"
	"github.com/containerd/errdefs"
	"github.com/pkg/errors"
)

func (s *service) createSandbox(
	ctx context.Context,
	sandboxId string,
	rootfs []*types.Mount,
	bundle string,
	sandboxSpec *sandbox_options.SandboxSpec,
) (*sandbox.CreateSandboxResponse, error) {
	// We are not actively using Sandbox Options and therefore, we are omitting unmarshalling them.

	// Return error on older versions of Windows.
	if osversion.Build() < osversion.RS5 {
		return nil, errors.Wrapf(errdefs.ErrFailedPrecondition, "pod support is not available on Windows versions previous to RS5 (%d)", osversion.RS5)
	}

	// For process-isolation, this API will
	if sandboxSpec.GetIsolationLevel() != nil && sandboxSpec.GetProcess() != nil {
		log.G(ctx).Info("creating sandbox with process isolation level is not supported")
		// Instead of returning an error, make it a no-op.
		// This is because for process-isolated cases, CRI can call into Task API
		// to create the pause container which will hold the pod namespace open.
		// Therefore, same workflow can be used by CRI for all types of containers.
		return &sandbox.CreateSandboxResponse{}, nil
	}

	// Hold the lock on service mutex prior to starting a new sandbox.
	// This is needed to avoid any race conditions.
	s.cl.Lock()

	// If the sandbox was already created, or is not managed by the sandbox API,
	// return an error.
	if s.sandbox.phase != sandboxUnknown {
		s.cl.Unlock()
		return nil, fmt.Errorf("invalid phase %s of sandbox", s.sandbox.phase.String())
	}

	// Create the LCOW or WCOW options and save them.
	owner := filepath.Base(os.Args[0])
	lcowOptions, wcowOptions, plat, err := sandbox_options.BuildUVMOptions(ctx, sandboxSpec, fmt.Sprintf("%s@vm", sandboxId), owner)
	if err != nil {
		s.cl.Unlock()
		return nil, fmt.Errorf("failed to build uvm options: %w", err)
	}

	var host *uvm.UtilityVM
	if lcowOptions != nil {
		lcowOptions.BundleDirectory = bundle
		host, err = uvm.CreateLCOW(ctx, lcowOptions)
		if err != nil {
			s.cl.Unlock()
			return nil, fmt.Errorf("failed to create lcow uvm: %w", err)
		}
	}

	if wcowOptions != nil {
		err = initializeWCOWBootFiles(ctx, wcowOptions, rootfs, []string{})
		if err != nil {
			s.cl.Unlock()
			return nil, fmt.Errorf("failed to initialize wcow boot files: %w", err)
		}

		host, err = uvm.CreateWCOW(ctx, wcowOptions)
		if err != nil {
			s.cl.Unlock()
			return nil, fmt.Errorf("failed to create wcow uvm: %w", err)
		}
	}

	s.sandbox.host = host
	s.sandbox.lcowOptions = lcowOptions
	s.sandbox.wcowOptions = wcowOptions

	// Set the sandbox params.
	s.sandbox.phase = sandboxCreated
	s.sandbox.id = sandboxId
	s.sandbox.platform = plat
	// For the workflow via CreateSandbox, we need to mark this field as true
	s.isSandbox = true

	s.cl.Unlock()
	return &sandbox.CreateSandboxResponse{}, nil
}

func (s *service) startSandbox(ctx context.Context, sandboxId string) (*sandbox.StartSandboxResponse, error) {
	s.cl.Lock()
	if s.sandbox.id != sandboxId {
		s.cl.Unlock()
		return &sandbox.StartSandboxResponse{}, fmt.Errorf("invalid sandbox id")
	}

	if s.sandbox.phase != sandboxCreated {
		s.cl.Unlock()
		return &sandbox.StartSandboxResponse{}, fmt.Errorf("invalid sandbox phase")
	}

	err := s.sandbox.host.Start(ctx)
	if err != nil {
		s.cl.Unlock()
		return &sandbox.StartSandboxResponse{}, fmt.Errorf("failed to start sandbox: %w", err)
	}

	return &sandbox.StartSandboxResponse{}, nil
}

func (s *service) platform(_ context.Context, sandboxId string) (*sandbox.PlatformResponse, error) {
	if s.sandbox.id != sandboxId {
		return &sandbox.PlatformResponse{}, fmt.Errorf("invalid sandbox id")
	}

	if s.sandbox.phase == sandboxUnknown || s.sandbox.phase == sandboxPodManaged {
		return &sandbox.PlatformResponse{}, fmt.Errorf("invalid sandbox phase")
	}

	return &sandbox.PlatformResponse{
		Platform: &types.Platform{
			OS:           s.sandbox.platform.OS,
			Architecture: s.sandbox.platform.Architecture,
			Variant:      s.sandbox.platform.Variant,
			OSVersion:    s.sandbox.platform.OSVersion,
		},
	}, nil
}

func (s *service) stopSandbox(ctx context.Context, request *sandbox.StopSandboxRequest) (*sandbox.StopSandboxResponse, error) {
	return nil, nil
}

func (s *service) waitSandbox(ctx context.Context, sandboxId string) (*sandbox.WaitSandboxResponse, error) {
	if s.sandbox.id != sandboxId {
		return &sandbox.WaitSandboxResponse{}, fmt.Errorf("invalid sandbox id")
	}

	if s.sandbox.phase != sandboxStarted {
		return &sandbox.WaitSandboxResponse{}, fmt.Errorf("sandbox not started")
	}

	err := s.sandbox.host.WaitCtx(ctx)
	if err != nil {
		return &sandbox.WaitSandboxResponse{}, err
	}

	// Todo: Implement pathway for sandbox status and set the exited params.
	return &sandbox.WaitSandboxResponse{}, nil
}

func (s *service) sandboxStatus(ctx context.Context, request *sandbox.SandboxStatusRequest) (*sandbox.SandboxStatusResponse, error) {
	// Todo: Implement the status method.
	return nil, nil
}

func (s *service) pingSandbox(ctx context.Context, sandboxId string) (*sandbox.PingResponse, error) {
	if s.sandbox.id != sandboxId {
		return &sandbox.PingResponse{}, fmt.Errorf("invalid sandbox id")
	}

	if s.sandbox.phase != sandboxStarted {
		return &sandbox.PingResponse{}, fmt.Errorf("sandbox not started")
	}

	isStopped := s.sandbox.host.IsStopped()
	if isStopped {
		return &sandbox.PingResponse{}, fmt.Errorf("sandbox is stopped")
	}

	return &sandbox.PingResponse{}, nil
}

func (s *service) shutdownSandbox(ctx context.Context, request *sandbox.ShutdownSandboxRequest) (*sandbox.ShutdownSandboxResponse, error) {
	return nil, nil
}

func (s *service) sandboxMetrics(ctx context.Context, request *sandbox.SandboxMetricsRequest) (*sandbox.SandboxMetricsResponse, error) {
	return nil, nil
}
