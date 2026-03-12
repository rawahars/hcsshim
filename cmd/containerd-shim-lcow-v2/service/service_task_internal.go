//go:build windows

package service

import (
	"context"

	"github.com/containerd/containerd/api/runtime/task/v3"
	"github.com/containerd/errdefs"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *Service) stateInternal(ctx context.Context, request *task.StateRequest) (*task.StateResponse, error) {
	_ = ctx
	_ = request
	return nil, errdefs.ErrNotImplemented
}

func (s *Service) createInternal(ctx context.Context, request *task.CreateTaskRequest) (*task.CreateTaskResponse, error) {
	_ = ctx
	_ = request
	return nil, errdefs.ErrNotImplemented
}

func (s *Service) startInternal(ctx context.Context, request *task.StartRequest) (*task.StartResponse, error) {
	_ = ctx
	_ = request
	return nil, errdefs.ErrNotImplemented
}

func (s *Service) deleteInternal(ctx context.Context, request *task.DeleteRequest) (*task.DeleteResponse, error) {
	_ = ctx
	_ = request
	return nil, errdefs.ErrNotImplemented
}

func (s *Service) pidsInternal(ctx context.Context, request *task.PidsRequest) (*task.PidsResponse, error) {
	_ = ctx
	_ = request
	return nil, errdefs.ErrNotImplemented
}

func (s *Service) pauseInternal(ctx context.Context, request *task.PauseRequest) (*emptypb.Empty, error) {
	_ = ctx
	_ = request
	return nil, errdefs.ErrNotImplemented
}

func (s *Service) resumeInternal(ctx context.Context, request *task.ResumeRequest) (*emptypb.Empty, error) {
	_ = ctx
	_ = request
	return nil, errdefs.ErrNotImplemented
}

func (s *Service) checkpointInternal(ctx context.Context, request *task.CheckpointTaskRequest) (*emptypb.Empty, error) {
	_ = ctx
	_ = request
	return nil, errdefs.ErrNotImplemented
}

func (s *Service) killInternal(ctx context.Context, request *task.KillRequest) (*emptypb.Empty, error) {
	_ = ctx
	_ = request
	return nil, errdefs.ErrNotImplemented
}

func (s *Service) execInternal(ctx context.Context, request *task.ExecProcessRequest) (*emptypb.Empty, error) {
	_ = ctx
	_ = request
	return nil, errdefs.ErrNotImplemented
}

func (s *Service) resizePtyInternal(ctx context.Context, request *task.ResizePtyRequest) (*emptypb.Empty, error) {
	_ = ctx
	_ = request
	return nil, errdefs.ErrNotImplemented
}

func (s *Service) closeIOInternal(ctx context.Context, request *task.CloseIORequest) (*emptypb.Empty, error) {
	_ = ctx
	_ = request
	return nil, errdefs.ErrNotImplemented
}

func (s *Service) updateInternal(ctx context.Context, request *task.UpdateTaskRequest) (*emptypb.Empty, error) {
	_ = ctx
	_ = request
	return nil, errdefs.ErrNotImplemented
}

func (s *Service) waitInternal(ctx context.Context, request *task.WaitRequest) (*task.WaitResponse, error) {
	_ = ctx
	_ = request
	return nil, errdefs.ErrNotImplemented
}

func (s *Service) statsInternal(ctx context.Context, request *task.StatsRequest) (*task.StatsResponse, error) {
	// todo: Here check if the ID in request is same as the podID but the container does not exist.
	// In such a case fetch stats from vmController. If container is present, then fetch it from Container.
	// Alternatively, just fetch container stats from container and VM stats from vmController and return both in response.
	_ = ctx
	_ = request
	return nil, errdefs.ErrNotImplemented
}

func (s *Service) connectInternal(ctx context.Context, request *task.ConnectRequest) (*task.ConnectResponse, error) {
	_ = ctx
	_ = request
	return nil, errdefs.ErrNotImplemented
}

func (s *Service) shutdownInternal(ctx context.Context, request *task.ShutdownRequest) (*emptypb.Empty, error) {
	_ = ctx
	_ = request
	return nil, errdefs.ErrNotImplemented
}
