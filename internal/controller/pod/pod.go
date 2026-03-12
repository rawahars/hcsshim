//go:build windows

package pod

import (
	"context"
	"fmt"
	"sync"

	"github.com/Microsoft/hcsshim/internal/controller/container"
	"github.com/Microsoft/hcsshim/internal/controller/network"
	"github.com/Microsoft/hcsshim/internal/controller/vm"
)

// Manager is the concrete implementation of Controller.
// It owns the network controller and all container controllers for a single pod.
type Manager struct {
	mu sync.Mutex

	// podID is the containerd sandbox / pod identifier.
	podID string

	// vmHandle provides access to the underlying VM's host and guest surfaces
	// and is used to wait for the VM to exit.
	// This is a subset interface of [vm.Controller] interface.
	vmHandle vm.Handle

	// networkCtrl manages the network namespace and endpoint lifecycle for this pod.
	networkCtrl network.Controller

	// containers maps containerID -> ContainerController for all live containers.
	containers map[string]*container.Manager
}

var _ Controller = (*Manager)(nil)

// New creates a ready-to-use Manager for the given pod.
func New(
	podID string,
	vmLifetime vm.Handle,
) *Manager {
	return &Manager{
		podID:       podID,
		vmHandle:    vmLifetime,
		networkCtrl: network.New(podID, vmLifetime.Host(), vmLifetime.Guest(), vmLifetime.Guest()),
		containers:  make(map[string]*container.Manager),
	}
}

func (p *Manager) SetupNetwork(ctx context.Context, opts *SetupNetworkOptions) error {
	err := p.networkCtrl.Setup(ctx, &network.SetupOptions{
		NetworkNamespace: opts.NetworkNamespace,
		EndpointIDs:      opts.EndpointIDs,
	})
	if err != nil {
		return fmt.Errorf("failed in pod.SetupNetwork: %w", err)
	}

	return nil
}

func (p *Manager) TeardownNetwork(ctx context.Context) error {
	if err := p.networkCtrl.Teardown(ctx); err != nil {
		return fmt.Errorf("failed in pod.TeardownNetwork: %w", err)
	}
	return nil
}

func (p *Manager) GetContainer(containerID string) (*container.Manager, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	c, ok := p.containers[containerID]
	if !ok {
		return nil, fmt.Errorf("container %q not found in pod %q", containerID, p.podID)
	}

	return c, nil
}

func (p *Manager) NewContainer(containerID string) (*container.Manager, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, ok := p.containers[containerID]; ok {
		return nil, fmt.Errorf("container %q already exists in pod %q", containerID, p.podID)
	}

	mgr := container.New(containerID, p.vmHandle, p.vmHandle.Guest())
	p.containers[containerID] = mgr

	return mgr, nil
}

func (p *Manager) ListContainers() (map[string]*container.Manager, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	result := make(map[string]*container.Manager, len(p.containers))
	for id, mgr := range p.containers {
		result[id] = mgr
	}

	return result, nil
}
