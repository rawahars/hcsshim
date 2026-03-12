//go:build windows

package scsi

import (
	"context"
	"fmt"
	"sync"

	"github.com/Microsoft/hcsshim/internal/controller/vm"
	"github.com/Microsoft/hcsshim/internal/vm/guestmanager"
	"github.com/Microsoft/hcsshim/internal/vm/vmmanager"
)

// ControllerCore is the concrete implementation of Controller.
// It wraps the host-side SCSIManager and the guest-side LCOWScsiManager
// and owns the slot allocation table.
type ControllerCore struct {
	mu sync.Mutex

	// hostMgr performs the HCS modify calls to add/remove SCSI disks on the UVM.
	hostMgr vmmanager.SCSIManager
	// guestMgr sends GCS requests to map/unmap the disk inside the UVM guest.
	guestMgr guestmanager.LCOWScsiManager

	// allocations maps containerID -> list of active Allocation entries.
	allocations map[string][]*Allocation
}

var _ Controller = (*ControllerCore)(nil)

// New creates a ready-to-use ControllerCore.
func New(vmHandle vm.Handle) *ControllerCore {
	return &ControllerCore{
		allocations: make(map[string][]*Allocation),
	}
}

// Attach hot-adds a SCSI disk to the UVM host side and notifies the guest.
func (c *ControllerCore) Attach(ctx context.Context, containerID string, opts *AttachOptions) (*Allocation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// TODO: Phase C – allocate a free (controller, lun) slot from the slot table.
	// TODO: Call c.hostMgr.AddSCSIDisk with the resolved hcsschema.Attachment.
	// TODO: Call c.guestMgr.AddLCOWMappedVirtualDisk to notify the guest.
	// TODO: Record the Allocation in c.allocations[containerID].

	return nil, fmt.Errorf("scsi.Attach: not implemented")
}

// Detach removes the SCSI device from the guest and then from the UVM.
func (c *ControllerCore) Detach(ctx context.Context, containerID string, alloc *Allocation) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// TODO: Phase Container Delete – call c.guestMgr.RemoveLCOWMappedVirtualDisk.
	// TODO: Call c.hostMgr.RemoveSCSIDisk to release the host-side slot.
	// TODO: Remove the Allocation from c.allocations[containerID].
	// TODO: Free the (controller, lun) slot back to the pool.

	return fmt.Errorf("scsi.Detach: not implemented")
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
