//go:build windows

package process

import (
	"context"

	"github.com/containerd/containerd/api/runtime/task/v3"
	"github.com/opencontainers/runtime-spec/specs-go"
)

type Controller interface {
	Pid() int

	Create(ctx context.Context, opts *CreateOptions) error

	Start(ctx context.Context) (int, error)

	Status(verbose bool) *task.StateResponse

	ResizeConsole(ctx context.Context, width, height uint32) error

	CloseIO(ctx context.Context)

	Wait(ctx context.Context)
}

type CreateOptions struct {
	Bundle string

	Spec *specs.Process

	Terminal bool

	Stdin string

	Stdout string

	Stderr string
}
