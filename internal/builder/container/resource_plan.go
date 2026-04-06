//go:build windows

package container

import (
	"context"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Microsoft/hcsshim/internal/log"
)

// ResourcePlan holds all host-side resource reservations for a container.
type ResourcePlan struct {
	// SCSILayers holds the read-only and scratch layer SCSI reservations.
	SCSILayers *SCSILayerPlan
	// SCSI holds non-layer SCSI mount reservations (virtual-disk, physical-disk, EVD).
	SCSI []guid.GUID
	// Plan9 holds Plan9 share reservations for bind mounts.
	Plan9 []guid.GUID
	// Devices holds vPCI / GPU device reservations.
	Devices []guid.GUID
}

// Release undoes every reservation held by the plan in reverse allocation order.
// Errors are logged but do not stop the remaining cleanup.
func (rp *ResourcePlan) Release(ctx context.Context, scsi SCSIReserver, plan9 Plan9Reserver, vpci VPCIReserver) {
	if rp == nil {
		return
	}

	log.G(ctx).Debug("releasing all resource reservations")

	// Plan9 shares.
	for _, reservationID := range rp.Plan9 {
		if err := plan9.UnmapFromGuest(ctx, reservationID); err != nil {
			log.G(ctx).WithError(err).Error("failed to release plan9 share reservation")
		}
	}

	// VPCI devices.
	for _, deviceID := range rp.Devices {
		if err := vpci.RemoveFromVM(ctx, deviceID); err != nil {
			log.G(ctx).WithError(err).Error("failed to release vpci device reservation")
		}
	}

	// SCSI mounts (non-layer).
	for _, reservationID := range rp.SCSI {
		if err := scsi.UnmapFromGuest(ctx, reservationID); err != nil {
			log.G(ctx).WithError(err).Error("failed to release scsi mount reservation")
		}
	}

	// If there were no layer reservations, then we can return.
	if rp.SCSILayers == nil {
		return
	}

	// Scratch layer — zero GUID means it was never reserved.
	if rp.SCSILayers.Scratch.ID != (guid.GUID{}) {
		if err := scsi.UnmapFromGuest(ctx, rp.SCSILayers.Scratch.ID); err != nil {
			log.G(ctx).WithError(err).Error("failed to release scratch layer reservation")
		}
	}

	// Read-only layers.
	for _, layer := range rp.SCSILayers.ROLayers {
		if err := scsi.UnmapFromGuest(ctx, layer.ID); err != nil {
			log.G(ctx).WithError(err).Error("failed to release read-only layer reservation")
		}
	}

	log.G(ctx).Debug("all resource reservations released")
}
