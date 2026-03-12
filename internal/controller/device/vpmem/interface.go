//go:build windows

// Package vpmem provides a controller for managing Virtual Persistent Memory (VPMem)
// device lifecycle across both the host (UVM) and guest (GCS) sides.  It coordinates
// between vmmanager.VPMemManager (host HCS calls) and guestmanager.LCOWDeviceManager
// (guest GCS calls), and maintains a per-container mapping of VPMem slot IDs.
package vpmem

import "context"

// Controller manages the lifecycle of VPMem devices attached to a UVM.
type Controller interface {
	// Attach adds a VPMem device to the UVM host side and notifies the guest,
	// associating the device with containerID.
	// Returns the Allocation which must be retained for later Detach calls.
	Attach(ctx context.Context, containerID string, opts *AttachOptions) (*Allocation, error)

	// Detach removes the VPMem device from the guest and then from the UVM host.
	// alloc is the value returned by a prior Attach call.
	Detach(ctx context.Context, containerID string, alloc *Allocation) error

	// Allocations returns a snapshot of all live allocations keyed by containerID.
	Allocations() map[string][]*Allocation
}

// AttachOptions describes the VPMem device to attach.
type AttachOptions struct {
	// HostPath is the path on the Windows host to the VHD exposed as VPMem.
	HostPath string
	// ReadOnly indicates the device should be attached read-only.
	ReadOnly bool
}

// Allocation records the host-side slot ID and guest-side device path resulting
// from a successful Attach call.
type Allocation struct {
	// SlotID is the VPMem device slot index on the UVM host side (0-based).
	SlotID uint32
	// GuestDevicePath is the pmem device path inside the UVM guest (e.g. /dev/pmem0).
	GuestDevicePath string
	// HostPath mirrors AttachOptions.HostPath for bookkeeping.
	HostPath string
}
