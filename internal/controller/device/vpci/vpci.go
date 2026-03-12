//go:build windows

package vpci

import (
	"context"
	"fmt"
	"sync"

	"github.com/Microsoft/hcsshim/internal/vm/guestmanager"
	"github.com/Microsoft/hcsshim/internal/vm/vmmanager"
)

// ControllerCore is the concrete implementation of Controller.
type ControllerCore struct {
	mu sync.Mutex

	// hostMgr performs the HCS modify calls to add/remove PCI devices on the UVM.
	hostMgr vmmanager.PCIManager
	// guestMgr sends GCS requests to expose the device inside the UVM guest.
	guestMgr guestmanager.LCOWDeviceManager

	// allocations maps containerID -> list of active Allocation entries.
	allocations map[string][]*Allocation
}

var _ Controller = (*ControllerCore)(nil)

// New creates a ready-to-use ControllerCore.
func New(hostMgr vmmanager.PCIManager, guestMgr guestmanager.LCOWDeviceManager) *ControllerCore {
	return &ControllerCore{
		hostMgr:     hostMgr,
		guestMgr:    guestMgr,
		allocations: make(map[string][]*Allocation),
	}
}

// Assign hot-plugs a PCI device into the UVM and notifies the guest.
func (c *ControllerCore) Assign(ctx context.Context, containerID string, opts *AssignOptions) (*Allocation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// TODO: Phase C – call c.hostMgr.AddDevice with the resolved hcsschema.VirtualPciDevice.
	// TODO: Call c.guestMgr.AddVPCIDevice with the guest-side LCOWMappedVPCIDevice settings.
	// TODO: Record the Allocation in c.allocations[containerID].

	return nil, fmt.Errorf("vpci.Assign: not implemented")
}

// Release removes the PCI device from the guest and then from the UVM.
func (c *ControllerCore) Release(ctx context.Context, containerID string, alloc *Allocation) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// TODO: Phase Container Delete – no guest-side remove for VPCI (guest detects hot-unplug).
	// TODO: Call c.hostMgr.RemoveDevice to remove the device from the UVM.
	// TODO: Remove the Allocation from c.allocations[containerID].

	return fmt.Errorf("vpci.Release: not implemented")
}

// Allocations returns a snapshot of all live allocations keyed by containerID.
func (c *ControllerCore) Allocations() map[string][]*Allocation {
	c.mu.Lock()
	defer c.mu.Unlock()

	snapshot := make(map[string][]*Allocation, len(c.allocations))
	for k, v := range c.allocations {
		snapshot[k] = v
	}
	return snapshot
}
