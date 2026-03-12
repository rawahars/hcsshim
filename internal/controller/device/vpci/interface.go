//go:build windows

// Package vpci provides a controller for managing Virtual PCI device lifecycle
// across both the host (UVM) and guest (GCS) sides.  It coordinates between
// vmmanager.PCIManager (host HCS calls) and guestmanager.LCOWDeviceManager
// (guest GCS calls), and maintains a per-container mapping of VMBus GUIDs.
package vpci

import "context"

// Controller manages the lifecycle of VPCI devices attached to a UVM.
type Controller interface {
	// Assign hot-plugs the PCI device identified by vmbusGUID into the UVM and
	// notifies the guest, associating the device with containerID.
	// Returns the Allocation which must be retained for later Release calls.
	Assign(ctx context.Context, containerID string, opts *AssignOptions) (*Allocation, error)

	// Release removes the PCI device from the guest and then from the UVM host.
	// alloc is the value returned by a prior Assign call.
	Release(ctx context.Context, containerID string, alloc *Allocation) error

	// Allocations returns a snapshot of all live allocations keyed by containerID.
	Allocations() map[string][]*Allocation
}

// AssignOptions describes the PCI device to assign.
type AssignOptions struct {
	// VMBusGUID is the VMBus channel GUID that identifies the PCI device to the host.
	VMBusGUID string
	// InstanceID is the instance ID of the PCI device (used for the guest-side path).
	InstanceID string
}

// Allocation records the host-side VMBus GUID and guest-side device information
// resulting from a successful Assign call.
type Allocation struct {
	// VMBusGUID is the VMBus channel GUID on the host side.
	VMBusGUID string
	// GuestInstanceID is the device instance ID visible inside the UVM guest.
	GuestInstanceID string
}
