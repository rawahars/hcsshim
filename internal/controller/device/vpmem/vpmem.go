//go:build windows

package vpmem

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

	// hostMgr performs the HCS modify calls to add/remove VPMem devices on the UVM.
	hostMgr vmmanager.VPMemManager
	// guestMgr sends GCS requests to expose the device inside the UVM guest.
	guestMgr guestmanager.LCOWDeviceManager

	// allocations maps containerID -> list of active Allocation entries.
	allocations map[string][]*Allocation

	// nextSlot tracks the next available VPMem slot.
	// TODO: Replace with a proper free-list or bitmap once slot limits are known.
	nextSlot uint32
}

var _ Controller = (*ControllerCore)(nil)

// New creates a ready-to-use ControllerCore.
func New(hostMgr vmmanager.VPMemManager, guestMgr guestmanager.LCOWDeviceManager) *ControllerCore {
	return &ControllerCore{
		hostMgr:     hostMgr,
		guestMgr:    guestMgr,
		allocations: make(map[string][]*Allocation),
	}
}

// Attach adds a VPMem device to the UVM host side and notifies the guest.
func (c *ControllerCore) Attach(ctx context.Context, containerID string, opts *AttachOptions) (*Allocation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// TODO: Phase C – allocate a free slot from c.nextSlot / a free-list.
	// TODO: Build hcsschema.VirtualPMemDevice from opts and call c.hostMgr.AddVPMemDevice.
	// TODO: Call c.guestMgr.AddVPMemDevice with the guest-side LCOWMappedVPMemDevice settings.
	// TODO: Record the Allocation in c.allocations[containerID].

	return nil, fmt.Errorf("vpmem.Attach: not implemented")
}

// Detach removes the VPMem device from the guest and then from the UVM.
func (c *ControllerCore) Detach(ctx context.Context, containerID string, alloc *Allocation) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// TODO: Phase Container Delete – call c.guestMgr.RemoveVPMemDevice.
	// TODO: Call c.hostMgr.RemoveVPMemDevice to release the host-side slot.
	// TODO: Remove the Allocation from c.allocations[containerID] and free the slot.

	return fmt.Errorf("vpmem.Detach: not implemented")
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
