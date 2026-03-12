//go:build windows

package network

import (
	"context"
	"fmt"
	"sync"

	"github.com/Microsoft/hcsshim/internal/vm/guestmanager"
	"github.com/Microsoft/hcsshim/internal/vm/vmmanager"
)

// Manager is the concrete implementation of Controller.
type Manager struct {
	mu sync.Mutex

	// podID scopes all network operations for a pod with given ID.
	podID string

	hostMgr vmmanager.NetworkManager

	linuxGuestMgr guestmanager.LCOWNetworkManager

	windowsGuestMgr guestmanager.WCOWNetworkManager

	// status is the live network state, populated during Setup and cleared by Teardown.
	status *Status
}

var _ Controller = (*Manager)(nil)

func New(
	podID string,
	hostMgr vmmanager.NetworkManager,
	linuxGuestMgr guestmanager.LCOWNetworkManager,
	windowsGuestMgr guestmanager.WCOWNetworkManager,
) *Manager {
	return &Manager{
		podID:           podID,
		hostMgr:         hostMgr,
		linuxGuestMgr:   linuxGuestMgr,
		windowsGuestMgr: windowsGuestMgr,
		status:          &Status{},
	}
}

// Setup creates the network namespace, attaches HCN endpoints, and injects
// guest-side NICs into the UVM.
func (c *Manager) Setup(ctx context.Context, opts *SetupOptions) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// TODO: Phase B – Create or join the HCN network namespace identified by
	//        opts.NetworkNamespacePath / opts.EndpointIDs.
	// TODO: For each endpoint in opts.EndpointIDs call hcn to attach the endpoint
	//        to the namespace and retrieve the LCOWNetworkAdapter settings.
	// TODO: Call c.guestMgr.AddLCOWNetworkInterface for each adapter.
	// TODO: Populate c.status with namespace ID, endpoint IDs and guest adapter names.

	return fmt.Errorf("network.Setup: not implemented")
}

// Teardown removes guest NICs, detaches HCN endpoints, and destroys the namespace.
func (c *Manager) Teardown(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// TODO: Phase Pod Delete – for each guest adapter call c.guestMgr.RemoveLCOWNetworkInterface.
	// TODO: Detach and delete HCN endpoints.
	// TODO: Delete the HCN network namespace if we created it.
	// TODO: Clear c.status.

	return fmt.Errorf("network.Teardown: not implemented")
}

// Status returns a snapshot of the current network state.
func (c *Manager) Status() *Status {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.status == nil {
		return &Status{}
	}
	// Return a shallow copy to avoid callers mutating internal state.
	s := *c.status
	return &s
}
