//go:build windows

package shimdiag

import (
	"context"

	"github.com/Microsoft/hcsshim/internal/shimdiag"
)

type service struct{}

var _ shimdiag.ShimDiagService = &service{}

func (s service) DiagExecInHost(ctx context.Context, request *shimdiag.ExecProcessRequest) (*shimdiag.ExecProcessResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (s service) DiagStacks(ctx context.Context, request *shimdiag.StacksRequest) (*shimdiag.StacksResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (s service) DiagTasks(ctx context.Context, request *shimdiag.TasksRequest) (*shimdiag.TasksResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (s service) DiagShare(ctx context.Context, request *shimdiag.ShareRequest) (*shimdiag.ShareResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (s service) DiagPid(ctx context.Context, request *shimdiag.PidRequest) (*shimdiag.PidResponse, error) {
	//TODO implement me
	panic("implement me")
}
