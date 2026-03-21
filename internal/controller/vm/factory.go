//go:build windows

package vm

import (
	"github.com/Microsoft/hcsshim/internal/controller/device/scsi"
	"github.com/Microsoft/hcsshim/internal/controller/network"
)

func (m *Manager) CreateNetworkController() *network.Manager {
	return network.New(m.uvm, m.guest, m.guest, m.guest)
}

func (m *Manager) CreateSCSIController(
	numControllers int,
	reservedSlots []scsi.VMSlot,
) *scsi.Manager {
	// m.guest satisfies both LCOWScsiManager and WCOWScsiManager.
	// New stores both; exactly one will be exercised at runtime depending
	// on the guest OS type.
	return scsi.New(m.uvm, m.guest, numControllers, reservedSlots)
}
