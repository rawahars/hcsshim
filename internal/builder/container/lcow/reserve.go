//go:build windows && lcow

package lcow

import (
	"context"
	"fmt"

	"github.com/Microsoft/hcsshim/internal/builder/container"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/logfields"
	containerdtypes "github.com/containerd/containerd/api/types"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

// ReserveConfig holds all inputs needed by [ReserveAll].
type ReserveConfig struct {
	VMID             string
	PodID            string
	ContainerID      string
	Rootfs           []*containerdtypes.Mount
	ScratchEncrypted bool
}

// ReserveAll orchestrates reservation of all host-side resources for an LCOW
// container and rewrites the OCI spec in place so mount sources, device IDs,
// and root paths reference their guest-visible equivalents.
//
// On partial failure every previously successful reservation is released
// before the error is returned. On success the caller receives a
// [container.ResourcePlan] whose fields are individually trackable IDs
// suitable for save/restore during live migration.
func ReserveAll(
	ctx context.Context,
	scsiReserver container.SCSIReserver,
	plan9Reserver container.Plan9Reserver,
	vpciReserver container.VPCIReserver,
	spec *specs.Spec,
	cfg *ReserveConfig,
) (_ *container.ResourcePlan, err error) {

	log.G(ctx).WithFields(logrus.Fields{
		logfields.ContainerID: cfg.ContainerID,
		logfields.PodID:       cfg.PodID,
		logfields.UVMID:       cfg.VMID,
	}).Debug("reserving all host-side resources for LCOW container")

	// Build the plan incrementally. Each sub-function returns whatever it
	// successfully reserved even on error, so the single deferred Release
	// cleans up everything.
	plan := &container.ResourcePlan{}
	defer func() {
		if err != nil {
			log.G(ctx).WithError(err).Warn("reservation failed, releasing partially reserved resources")
			plan.Release(ctx, scsiReserver, plan9Reserver, vpciReserver)
		}
	}()

	// Phase 1: Reserve SCSI slots for read-only layers and the scratch layer.
	log.G(ctx).Debug("phase 1: reserving layers")
	plan.SCSILayers, err = parseAndReserveLayers(
		ctx,
		cfg.VMID,
		cfg.PodID,
		cfg.ContainerID,
		spec.Windows.LayerFolders,
		cfg.Rootfs,
		cfg.ScratchEncrypted,
		scsiReserver,
	)
	if err != nil {
		return nil, fmt.Errorf("reserve layers: %w", err)
	}

	// Set the container root path from the layer plan.
	if spec.Root == nil {
		spec.Root = &specs.Root{}
	}
	spec.Root.Path = plan.SCSILayers.RootfsGuestPath

	// Phase 2: Reserve SCSI and Plan9 resources for OCI mounts.
	log.G(ctx).Debug("phase 2: reserving mounts")
	plan.SCSI, plan.Plan9, err = reserveAndUpdateMounts(
		ctx, cfg.VMID, scsiReserver, plan9Reserver, spec.Mounts,
	)
	if err != nil {
		return nil, fmt.Errorf("reserve mounts: %w", err)
	}

	// Phase 3: Reserve vPCI devices.
	if spec.Windows != nil {
		log.G(ctx).Debug("phase 3: reserving vPCI devices")
		plan.Devices, err = reserveAndUpdateDevices(ctx, vpciReserver, spec.Windows.Devices)
		if err != nil {
			return nil, fmt.Errorf("reserve devices: %w", err)
		}
	}

	log.G(ctx).Info("all host-side resources reserved successfully for LCOW container")
	return plan, nil
}
