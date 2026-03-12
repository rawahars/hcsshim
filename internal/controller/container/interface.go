//go:build windows

package container

import (
	"context"

	"github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/stats"
	"github.com/Microsoft/hcsshim/internal/controller/process"
	"github.com/containerd/containerd/api/runtime/task/v3"
	containerdtypes "github.com/containerd/containerd/api/types/task"
)

// Controller manages the full lifecycle of a single container inside a UVM.
type Controller interface {
	ID() string

	Create(ctx context.Context, opts *task.CreateTaskRequest) error

	Start(ctx context.Context) (uint32, error)

	Update(ctx context.Context, resources interface{}, annotations map[string]string) error

	NewProcess(execID string) *process.Manager

	GetProcess(execID string) (*process.Manager, error)

	ListProcesses() (map[string]*process.Manager, error)

	Pids(ctx context.Context) ([]*containerdtypes.ProcessInfo, error)

	Stats(ctx context.Context) (*stats.Statistics, error)
}

// todo: add mutex locks
// todo: add status and it changes based on the transitions.
// todo: think about all cases of created to exit and other similar state transitions.
