//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/sandbox_options"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/uvm"
	"github.com/Microsoft/hcsshim/osversion"
	"github.com/containerd/typeurl/v2"
	"golang.org/x/sys/windows"

	"github.com/containerd/containerd/api/runtime/sandbox/v1"
	"github.com/containerd/containerd/api/types"
	"github.com/containerd/errdefs"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/types/known/timestamppb"
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

	// Ignore the error here since the start time should always be available after a successful start.
	startTime, _ := s.sandbox.host.StartTime()

	s.sandbox.phase = sandboxStarted
	s.cl.Unlock()

	return &sandbox.StartSandboxResponse{
		CreatedAt: timestamppb.New(startTime),
	}, nil
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

func (s *service) stopSandbox(ctx context.Context, sandboxId string) (*sandbox.StopSandboxResponse, error) {
	if s.sandbox.id != sandboxId {
		return &sandbox.StopSandboxResponse{}, fmt.Errorf("invalid sandbox id")
	}

	// Todo: Consider custom error for invalid phase.
	if s.sandbox.phase != sandboxStarted {
		return &sandbox.StopSandboxResponse{}, fmt.Errorf("invalid sandbox phase")
	}

	isStopped := s.sandbox.host.IsStopped()
	if !isStopped {
		err := s.sandbox.host.CloseCtx(ctx)
		if err != nil {
			return &sandbox.StopSandboxResponse{}, err
		}
	}

	return &sandbox.StopSandboxResponse{}, nil
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

	stopTime, err := s.sandbox.host.StopTime()
	if err != nil {
		return &sandbox.WaitSandboxResponse{}, fmt.Errorf("failed to get sandbox stop time: %w", err)
	}

	// Get the exit error for the uvm.
	exitStatus := 0
	// If there was an exit error, set a non-zero exit status.
	if exitError := s.sandbox.host.ExitError(); exitError != nil {
		exitStatus = int(windows.ERROR_INTERNAL_ERROR)
	}

	// Update the sandbox phase to terminated.
	s.sandbox.phase = sandboxTerminated

	return &sandbox.WaitSandboxResponse{
		ExitStatus: uint32(exitStatus),
		ExitedAt:   timestamppb.New(stopTime),
	}, nil
}

func (s *service) sandboxStatus(_ context.Context, sandboxId string, verbose bool) (*sandbox.SandboxStatusResponse, error) {
	if s.sandbox.id != sandboxId {
		return &sandbox.SandboxStatusResponse{}, fmt.Errorf("invalid sandbox id")
	}

	if s.sandbox.phase == sandboxPodManaged {
		return &sandbox.SandboxStatusResponse{}, fmt.Errorf("sandbox is pod managed")
	}

	resp := &sandbox.SandboxStatusResponse{
		SandboxID: s.sandbox.id,
		State:     SandboxStateNotReady,
	}

	if s.sandbox.phase == sandboxStarted {
		resp.State = SandboxStateReady
	}

	if !verbose {
		// If not verbose, return early.
		return resp, nil
	}

	if s.sandbox.phase == sandboxStarted || s.sandbox.phase == sandboxTerminated {
		// Ignore the error here since the start time should always be available after a successful start.
		startTime, _ := s.sandbox.host.StartTime()
		resp.CreatedAt = timestamppb.New(startTime)
	}

	if s.sandbox.phase == sandboxTerminated {
		// Ignore the error here since the stop time should always be available after a successful stop.
		stopTime, _ := s.sandbox.host.StopTime()
		resp.ExitedAt = timestamppb.New(stopTime)
	}

	// Todo: Add more verbose info if needed.

	return nil, nil
}

func (s *service) pingSandbox(_ context.Context, sandboxId string) (*sandbox.PingResponse, error) {
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

func (s *service) shutdownSandbox(ctx context.Context, sandboxId string) (*sandbox.ShutdownSandboxResponse, error) {
	if s.sandbox.id != sandboxId {
		return &sandbox.ShutdownSandboxResponse{}, fmt.Errorf("invalid sandbox id")
	}

	if s.sandbox.phase != sandboxTerminated {
		return &sandbox.ShutdownSandboxResponse{}, fmt.Errorf("sandbox not terminated")
	}

	// Use a goroutine to wait for the context to be done.
	// This allows us to return the response of the shutdown call prior to
	// the server being shut down.
	go func() {
		<-ctx.Done()
		time.Sleep(20 * time.Millisecond) // tiny cushion to avoid edge races

		// Along with terminating the UVM, signal the service to perform shutdown.
		s.shutdownOnce.Do(func() {
			s.gracefulShutdown = true
			close(s.shutdown)
		})
	}()

	return &sandbox.ShutdownSandboxResponse{}, nil
}

func (s *service) sandboxMetrics(ctx context.Context, sandboxId string) (*sandbox.SandboxMetricsResponse, error) {
	if s.sandbox.id != sandboxId {
		return &sandbox.SandboxMetricsResponse{}, fmt.Errorf("invalid sandbox id")
	}

	if s.sandbox.phase != sandboxStarted {
		return &sandbox.SandboxMetricsResponse{}, fmt.Errorf("sandbox not started")
	}

	stats, err := s.sandbox.host.Stats(ctx)
	if err != nil {
		return &sandbox.SandboxMetricsResponse{}, fmt.Errorf("failed to get sandbox metrics: %w", err)
	}

	anyStat, err := typeurl.MarshalAny(stats)
	if err != nil {
		return &sandbox.SandboxMetricsResponse{}, fmt.Errorf("failed to marshal sandbox metrics: %w", err)
	}

	return &sandbox.SandboxMetricsResponse{
		Metrics: &types.Metric{
			Timestamp: timestamppb.Now(),
			ID:        sandboxId,
			Data:      typeurl.MarshalProto(anyStat),
		},
	}, nil
}
