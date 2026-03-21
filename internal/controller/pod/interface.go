//go:build windows

package pod

import (
	"context"

	"github.com/Microsoft/hcsshim/internal/controller/container"
	"github.com/Microsoft/hcsshim/internal/controller/network"
)

// Controller manages the lifecycle of a single pod: its network namespace and
// all containers (including the infra/sandbox container) that run inside the pod.
type Controller interface {
	SetupNetwork(ctx context.Context, opts *network.SetupOptions) error

	TeardownNetwork(ctx context.Context) error

	NewContainer(containerID string) (*container.Manager, error)

	GetContainer(containerID string) (*container.Manager, error)

	ListContainers() (map[string]*container.Manager, error)

	//Delete(ctx context.Context) error
}

// todo: create status and it changes based on the tree below.
// todo: Consider case where sandbox container is not present but someone tries to use
// GetContainer with containerID as podID.
