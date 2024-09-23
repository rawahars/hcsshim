package taskserver

import (
	"context"
	"fmt"
	"time"

	"github.com/Microsoft/hcsshim/internal/cmd"
	"github.com/Microsoft/hcsshim/internal/core"
	"github.com/Microsoft/hcsshim/internal/shimdiag"
	"github.com/opencontainers/runtime-spec/specs-go"
)

var _ (shimdiag.ShimDiagService) = (*service)(nil)

func (s *service) DiagExecInHost(ctx context.Context, req *shimdiag.ExecProcessRequest) (*shimdiag.ExecProcessResponse, error) {
	io, err := cmd.NewUpstreamIO(ctx, "shimdiag", req.Stdout, req.Stderr, req.Stdin, req.Terminal, 5*time.Second)
	if err != nil {
		return nil, err
	}
	p, err := s.sandbox.Sandbox.CreateProcess(ctx, &core.ProcessConfig{
		ID: "shimdiag",
		Spec: &specs.Process{
			Args:     req.Args,
			Cwd:      req.Workdir,
			Terminal: req.Terminal,
		},
		IO: io,
	})
	if err != nil {
		return nil, err
	}
	if err := p.Start(ctx); err != nil {
		return nil, err
	}
	if err := p.Wait(ctx); err != nil {
		return nil, err
	}
	return &shimdiag.ExecProcessResponse{ExitCode: int32(p.Status().ExitCode())}, nil
}

func (s *service) DiagPid(ctx context.Context, req *shimdiag.PidRequest) (*shimdiag.PidResponse, error) {
	return nil, fmt.Errorf("unimplemented")
}

func (s *service) DiagShare(ctx context.Context, req *shimdiag.ShareRequest) (*shimdiag.ShareResponse, error) {
	return nil, fmt.Errorf("unimplemented")
}

func (s *service) DiagStacks(ctx context.Context, req *shimdiag.StacksRequest) (*shimdiag.StacksResponse, error) {
	return nil, fmt.Errorf("unimplemented")
}

func (s *service) DiagTasks(ctx context.Context, req *shimdiag.TasksRequest) (*shimdiag.TasksResponse, error) {
	return nil, fmt.Errorf("unimplemented")
}
