//go:build windows && lcow

package migration

import (
	"github.com/Microsoft/hcsshim/internal/controller/pod"
	"github.com/Microsoft/hcsshim/internal/controller/vm"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"

	"google.golang.org/protobuf/types/known/anypb"
)

type InitOptions struct {
	SessionID string

	Origin hcsschema.MigrationOrigin

	VMController *vm.Controller

	PodControllers map[string]*pod.Controller
}

type PrepareSourceOptions struct {
	InitOptions
	MigrationOpts *hcsschema.MigrationInitializeOptions
}

type ImportStateOptions struct {
	InitOptions

	SandboxID  string
	Checkpoint *anypb.Any
}

type PatchResourceOptions struct {
	// ContainerID identifies the imported container being patched.
	ContainerID string

	// Bundle is the destination-host bundle path for the container.
	Bundle string

	// RootfsMounts are the destination-host paths that back the container
	// rootfs (typically a stack of layer VHDs).
	RootfsMounts []string

	// Stdin, Stdout, Stderr are the destination-side named-pipe paths for
	// the container's primary IO. Empty when the container is detached.
	Stdin  string
	Stdout string
	Stderr string
}
