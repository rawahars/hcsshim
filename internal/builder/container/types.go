//go:build windows

package container

import (
	"context"

	plan9Mount "github.com/Microsoft/hcsshim/internal/controller/device/plan9/mount"
	"github.com/Microsoft/hcsshim/internal/controller/device/plan9/share"
	"github.com/Microsoft/hcsshim/internal/controller/device/scsi/disk"
	scsiMount "github.com/Microsoft/hcsshim/internal/controller/device/scsi/mount"
	"github.com/Microsoft/hcsshim/internal/controller/device/vpci"

	"github.com/Microsoft/go-winio/pkg/guid"
)

// MountReservation pairs a device mount reservation ID with its resolved guest path.
type MountReservation struct {
	ID        guid.GUID
	GuestPath string
}

// SCSILayerPlan holds the reservations and guest paths for a container's
// read-only layers, scratch layer, and rootfs, mounted via SCSI.
type SCSILayerPlan struct {
	// ROLayers holds the read-only layer reservations in overlay order.
	ROLayers []MountReservation
	// Scratch is the writable scratch layer reservation.
	Scratch MountReservation
	// RootfsGuestPath is the guest path where the container rootfs will be mounted.
	RootfsGuestPath string
}

// SCSIReserver reserves a SCSI disk and returns the reservation ID and guest path.
type SCSIReserver interface {
	Reserve(ctx context.Context, diskConfig disk.Config, mountConfig scsiMount.Config) (guid.GUID, string, error)
	UnmapFromGuest(ctx context.Context, reservation guid.GUID) error
}

// Plan9Reserver reserves a Plan9 share and returns the reservation ID and guest path.
type Plan9Reserver interface {
	Reserve(ctx context.Context, shareConfig share.Config, mountConfig plan9Mount.Config) (guid.GUID, string, error)
	UnmapFromGuest(ctx context.Context, reservation guid.GUID) error
}

// VPCIReserver reserves a vPCI device and returns the VMBus channel GUID.
type VPCIReserver interface {
	Reserve(ctx context.Context, device vpci.Device) (guid.GUID, error)
	RemoveFromVM(ctx context.Context, vmBusGUID guid.GUID) error
}
