//go:build windows

package task

import (
	"context"

	"github.com/containerd/containerd/api/runtime/task/v3"
	"google.golang.org/protobuf/types/known/emptypb"
)

type service struct{}

var _ task.TTRPCTaskService = &service{}

func (s service) State(ctx context.Context, request *task.StateRequest) (*task.StateResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (s service) Create(ctx context.Context, request *task.CreateTaskRequest) (*task.CreateTaskResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (s service) Start(ctx context.Context, request *task.StartRequest) (*task.StartResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (s service) Delete(ctx context.Context, request *task.DeleteRequest) (*task.DeleteResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (s service) Pids(ctx context.Context, request *task.PidsRequest) (*task.PidsResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (s service) Pause(ctx context.Context, request *task.PauseRequest) (*emptypb.Empty, error) {
	//TODO implement me
	panic("implement me")
}

func (s service) Resume(ctx context.Context, request *task.ResumeRequest) (*emptypb.Empty, error) {
	//TODO implement me
	panic("implement me")
}

func (s service) Checkpoint(ctx context.Context, request *task.CheckpointTaskRequest) (*emptypb.Empty, error) {
	//TODO implement me
	panic("implement me")
}

func (s service) Kill(ctx context.Context, request *task.KillRequest) (*emptypb.Empty, error) {
	//TODO implement me
	panic("implement me")
}

func (s service) Exec(ctx context.Context, request *task.ExecProcessRequest) (*emptypb.Empty, error) {
	//TODO implement me
	panic("implement me")
}

func (s service) ResizePty(ctx context.Context, request *task.ResizePtyRequest) (*emptypb.Empty, error) {
	//TODO implement me
	panic("implement me")
}

func (s service) CloseIO(ctx context.Context, request *task.CloseIORequest) (*emptypb.Empty, error) {
	//TODO implement me
	panic("implement me")
}

func (s service) Update(ctx context.Context, request *task.UpdateTaskRequest) (*emptypb.Empty, error) {
	//TODO implement me
	panic("implement me")
}

func (s service) Wait(ctx context.Context, request *task.WaitRequest) (*task.WaitResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (s service) Stats(ctx context.Context, request *task.StatsRequest) (*task.StatsResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (s service) Connect(ctx context.Context, request *task.ConnectRequest) (*task.ConnectResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (s service) Shutdown(ctx context.Context, request *task.ShutdownRequest) (*emptypb.Empty, error) {
	//TODO implement me
	panic("implement me")
}
