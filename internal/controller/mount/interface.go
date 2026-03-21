//go:build windows

package mount

import (
	"context"

	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
)

// Controller exposes guest mount operations.
type Controller interface {
	// Mount mounts a SCSI disk (identified by controller + LUN) inside the
	// guest at the path described by cfg.  Returns the resolved guest path.
	Mount(ctx context.Context, controller, lun uint, cfg MountConfig) (string, error)

	// Unmount releases a previously mounted guest path.  The controller and
	// LUN must match the values used in the corresponding Mount call.
	Unmount(ctx context.Context, controller, lun uint, guestPath string) error
}

// MountConfig describes how a SCSI disk should be mounted inside the guest.
type MountConfig struct {
	GuestPath        string
	Partition        uint64
	ReadOnly         bool
	Encrypted        bool
	Options          []string
	EnsureFilesystem bool
	Filesystem       string
	BlockDev         bool
	FormatWithRefs   bool
}

// LCOWGuestMounter performs LCOW guest mount/unmount operations.
type LCOWGuestMounter interface {
	AddLCOWMappedVirtualDisk(ctx context.Context, settings guestresource.LCOWMappedVirtualDisk) error
	RemoveLCOWMappedVirtualDisk(ctx context.Context, settings guestresource.LCOWMappedVirtualDisk) error
}

// WCOWGuestMounter performs WCOW guest mount/unmount operations.
type WCOWGuestMounter interface {
	AddWCOWMappedVirtualDisk(ctx context.Context, settings guestresource.WCOWMappedVirtualDisk) error
	AddWCOWMappedVirtualDiskForContainerScratch(ctx context.Context, settings guestresource.WCOWMappedVirtualDisk) error
	RemoveWCOWMappedVirtualDisk(ctx context.Context, settings guestresource.WCOWMappedVirtualDisk) error
}

// Internal data structures.

type guestMount struct {
	guestPath  string
	controller uint
	lun        uint
	config     *MountConfig
	refCount   uint
	state      mountState
}
