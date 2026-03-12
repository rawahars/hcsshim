//go:build windows

// Package scsi provides a controller for managing SCSI device lifecycle across both
// the host (UVM) and guest (GCS) sides. It coordinates between vmmanager.SCSIManager
// (host HCS calls) and guestmanager.LCOWScsiManager (guest GCS calls), and maintains
// a per-container mapping of SCSI slots to guest device paths.
package scsi

import "context"

// Controller manages the lifecycle of SCSI devices attached to a UVM.
// It maintains the slot allocation table and the container-to-device mapping
// needed for teardown during container or VM deletion.
type Controller interface {
	// Attach hot-adds the SCSI disk described by opts to the UVM and notifies
	// the guest, associating the device with containerID. It returns the
	// allocation that captures the host (controller/lun) and guest (/dev/sdX)
	// coordinates, which callers must retain for subsequent Detach calls.
	Attach(ctx context.Context, containerID string, opts *AttachOptions) (*Allocation, error)

	// Detach removes the SCSI device identified by alloc from the guest and
	// then from the UVM host side. The allocation is the value returned by a
	// prior Attach call.
	Detach(ctx context.Context, containerID string, alloc *Allocation) error

	// Allocations returns a snapshot of all live allocations keyed by
	// containerID. Used by PodController during recursive delete.
	Allocations() map[string][]*Allocation
}

// AttachOptions describes the disk to attach and how it should appear in the guest.
type AttachOptions struct {
	// HostPath is the path on the Windows host to the VHD or physical disk.
	HostPath string
	// ReadOnly indicates the disk should be attached read-only.
	ReadOnly bool
	// GuestMountPath is the desired mount point inside the UVM guest.
	// If empty the guest OS will choose a path.
	GuestMountPath string
}

// Allocation captures the result of a successful Attach call, recording both
// the host-side SCSI coordinates and the guest-side device node path.
type Allocation struct {
	// Controller is the SCSI controller index (0-3).
	Controller uint
	// LUN is the logical unit number on the controller (0-63).
	LUN uint
	// GuestDevicePath is the block device path inside the UVM (e.g. /dev/sdc).
	GuestDevicePath string
	// HostPath mirrors AttachOptions.HostPath for bookkeeping.
	HostPath string
}
