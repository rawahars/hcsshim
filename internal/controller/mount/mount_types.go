//go:build windows

package mount

import (
	"context"
	"sync"

	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
)

// ==============================================================================
// Exported data structures
// ==============================================================================

// SCSIMountConfig describes how a SCSI disk should be mounted inside the guest.
type SCSIMountConfig struct {
	// GuestPath is the path inside the guest where the disk will be mounted.
	// If empty, a unique path is generated automatically.
	GuestPath string
	// Partition is the target partition index (1-based) on a partitioned device.
	// Only supported for LCOW.
	Partition uint64
	// ReadOnly mounts the disk read-only.
	ReadOnly bool
	// Encrypted encrypts the device with dm-crypt.
	// Only supported for LCOW.
	Encrypted bool
	// Options are mount flags or data passed to the guest mount call.
	// Only supported for LCOW.
	Options []string
	// EnsureFilesystem formats the mount as Filesystem if not already formatted.
	// Only supported for LCOW.
	EnsureFilesystem bool
	// Filesystem is the target filesystem type.
	// Only supported for LCOW.
	Filesystem string
	// BlockDev mounts the device as a block device.
	// Only supported for LCOW.
	BlockDev bool
	// FormatWithRefs formats the disk using refs.
	// Only supported for WCOW scratch disks.
	FormatWithRefs bool
}

// Plan9MountConfig describes how a Plan9 share should be mounted inside the guest.
type Plan9MountConfig struct {
	// GuestPath is the path inside the guest where the share will be mounted.
	// If empty, a unique path is generated automatically.
	GuestPath string
	// ReadOnly mounts the share read-only.
	ReadOnly bool
}

// ==============================================================================
// Interfaces used by Manager to perform guest actions.
// ==============================================================================

// linuxGuestSCSI performs LCOW SCSI guest mount/unmount operations.
type linuxGuestSCSI interface {
	AddLCOWMappedVirtualDisk(ctx context.Context, settings guestresource.LCOWMappedVirtualDisk) error
	RemoveLCOWMappedVirtualDisk(ctx context.Context, settings guestresource.LCOWMappedVirtualDisk) error
}

// windowsGuestSCSI performs WCOW SCSI guest mount/unmount operations.
type windowsGuestSCSI interface {
	AddWCOWMappedVirtualDisk(ctx context.Context, settings guestresource.WCOWMappedVirtualDisk) error
	AddWCOWMappedVirtualDiskForContainerScratch(ctx context.Context, settings guestresource.WCOWMappedVirtualDisk) error
	RemoveWCOWMappedVirtualDisk(ctx context.Context, settings guestresource.WCOWMappedVirtualDisk) error
}

// linuxGuestPlan9 performs Plan9 guest mount/unmount operations in an LCOW guest.
type linuxGuestPlan9 interface {
	AddLCOWMappedDirectory(ctx context.Context, settings guestresource.LCOWMappedDirectory) error
	RemoveLCOWMappedDirectory(ctx context.Context, settings guestresource.LCOWMappedDirectory) error
}

// ==============================================================================
// Internal data structures
// ==============================================================================

// refTracker holds the per-mount concurrency and lifecycle fields shared by
// both scsiMount (SCSI) and plan9Mount (Plan9).
type refTracker struct {
	// mu serializes state transitions and broadcasts completion to concurrent
	// waiters: a goroutine that finds a Pending entry simply locks mu and waits
	// for the owner to move the state to Mounted or Invalid.
	mu sync.Mutex

	// state is the forward-only lifecycle position of this mount.
	// Access must be guarded by mu.
	state mountState

	// stateErr records the error that caused a transition to mountInvalid.
	// Waiters that find the mount in the invalid state return this error so
	// every caller sees the original failure reason.
	stateErr error

	// refCount is the number of active callers sharing this mount.
	// Access must be guarded by mu.
	refCount uint
}

// scsiMount tracks one SCSI disk mounted in the guest.
type scsiMount struct {
	refTracker

	guestPath  string
	controller uint
	lun        uint
	config     *SCSIMountConfig
}

// plan9Mount tracks one Plan9 share mounted in the guest.
type plan9Mount struct {
	refTracker

	// guestPath is the path inside the guest where the share is mounted.
	guestPath string
	// shareName is the Plan9 share name returned by [plan9.AddToVM].
	shareName string
	// config holds the mount options used when this share was first mounted.
	config *Plan9MountConfig
}
