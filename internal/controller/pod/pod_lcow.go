//go:build windows && lcow

package pod

import (
	"context"
	"fmt"
	"sync"

	"github.com/Microsoft/hcsshim/internal/controller/linuxcontainer"
	"github.com/Microsoft/hcsshim/internal/controller/network"
)

// Controller is the concrete implementation of Controller.
// It owns the network controller and all container controllers for a single pod.
type Controller struct {
	mu sync.Mutex

	// podID is the containerd sandbox / pod identifier.
	podID string

	gcsPodID string

	vm vmController
	// networkCtrl manages the network namespace and endpoint lifecycle for this pod.
	networkCtrl networkController

	// containers maps containerID -> ContainerController for all live containers.
	containers map[string]*linuxcontainer.Controller
}

func New(
	podID string,
	vm vmController,
) *Controller {
	return &Controller{
		podID: podID,
		// Same id is used as the container. GCS is tightly coupled with original ID.
		// Post migration, we can always change the primary ID while gcs used the original ID.
		gcsPodID:    podID,
		vm:          vm,
		networkCtrl: vm.NetworkController(),
		containers:  make(map[string]*linuxcontainer.Controller),
	}
}

func (c *Controller) SetupNetwork(ctx context.Context, opts *network.SetupOptions) error {
	err := c.networkCtrl.Setup(ctx, opts)
	if err != nil {
		return fmt.Errorf("failed in pod.SetupNetwork: %w", err)
	}

	return nil
}

func (c *Controller) TeardownNetwork(ctx context.Context) error {
	if err := c.networkCtrl.Teardown(ctx); err != nil {
		return fmt.Errorf("failed in pod.TeardownNetwork: %w", err)
	}
	return nil
}

func (c *Controller) GetContainer(containerID string) (*linuxcontainer.Controller, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	ctr, ok := c.containers[containerID]
	if !ok {
		return nil, fmt.Errorf("container %q not found in pod %q", containerID, c.podID)
	}

	return ctr, nil
}

func (c *Controller) NewContainer(containerID string) (*linuxcontainer.Controller, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.containers[containerID]; ok {
		return nil, fmt.Errorf("container %q already exists in pod %q", containerID, c.podID)
	}

	mgr := linuxcontainer.New(
		c.vm.RuntimeID(),
		c.gcsPodID,
		containerID,
		c.vm.Guest(),
		c.vm.SCSIController(),
		c.vm.Plan9Controller(),
		c.vm.VPCIController(),
	)
	c.containers[containerID] = mgr

	return mgr, nil
}

func (c *Controller) ListContainers() map[string]*linuxcontainer.Controller {
	c.mu.Lock()
	defer c.mu.Unlock()

	result := make(map[string]*linuxcontainer.Controller, len(c.containers))
	for id, mgr := range c.containers {
		result[id] = mgr
	}

	return result
}

// DeleteContainer removes a container from the pod's container map.
func (c *Controller) DeleteContainer(containerID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.containers[containerID]; !ok {
		return fmt.Errorf("container %q not found in pod %q", containerID, c.podID)
	}

	delete(c.containers, containerID)
	return nil
}

// todo: Listen for UVM exit and then mark all containers as stopped and do cleanup.
// Basically call delete on all containers.

// Do we need wait method?
// We wait on 2 things. If there is an init container, we wait on that.
// Secondly, we want on the vm to exit.
