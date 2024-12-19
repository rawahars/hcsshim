package core

import (
	"context"

	"github.com/Microsoft/hcsshim/internal/cmd"
	"github.com/Microsoft/hcsshim/internal/layers"
	statepkg "github.com/Microsoft/hcsshim/internal/state"
	"github.com/opencontainers/runtime-spec/specs-go"
)

type LinuxCtrConfig struct {
	ID         string
	OriginalID string
	Layers     *layers.LCOWLayers2
	Spec       *specs.Spec
	IO         cmd.UpstreamIO
}

type ProcessConfig struct {
	ID   string
	Spec *specs.Process
	IO   cmd.UpstreamIO
}

type GenericCompute interface {
	Start(ctx context.Context) error
	Wait(ctx context.Context) error
	Status() Status
	Pid() int
}

type ProcessLike interface {
	GenericCompute
	CloseIO(ctx context.Context)
	Signal(ctx context.Context, signal int) error
}

type Ctr interface {
	ProcessLike
	CreateProcess(ctx context.Context, c *ProcessConfig) (Process, error)
}

type Migrator interface {
	LMTransfer(ctx context.Context, socket uintptr) (Migrated, error)
}

type Migratable interface {
	Migrator
	LMPrepare(ctx context.Context) (*statepkg.SandboxState, *Resources, error)
	RestoreLinuxContainer(ctx context.Context, cid string, pid uint32, myIO cmd.UpstreamIO) (Ctr, error)
}

type Migrated interface {
	LMComplete(ctx context.Context) (Sandbox, error)
	LMKill(ctx context.Context) error
}

type Sandbox interface {
	GenericCompute
	CreateLinuxContainer(ctx context.Context, c *LinuxCtrConfig) (_ Ctr, err error)
	CreateProcess(ctx context.Context, c *ProcessConfig) (Process, error)
	Terminate(ctx context.Context) error
}

type Process interface {
	ProcessLike
}

type Status interface {
	Exited() bool
	ExitCode() int
}

type Resources struct {
	Layers []*LayersResource
}

type LayersResource struct {
	ResourceID  string
	ContainerID string
}

type Replacements struct {
	Layers []*LayersReplacement
}

type LayersReplacement struct {
	ResourceID string
	Layers     *layers.LCOWLayers2
}
