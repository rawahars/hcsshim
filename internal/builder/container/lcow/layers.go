//go:build windows && lcow

package lcow

import (
	"context"
	"fmt"

	"github.com/Microsoft/hcsshim/internal/builder/container"
	"github.com/Microsoft/hcsshim/internal/controller/device/scsi/disk"
	scsiMount "github.com/Microsoft/hcsshim/internal/controller/device/scsi/mount"
	"github.com/Microsoft/hcsshim/internal/guestpath"
	"github.com/Microsoft/hcsshim/internal/layers"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/logfields"
	"github.com/Microsoft/hcsshim/internal/ospath"
	"github.com/Microsoft/hcsshim/internal/wclayer"

	"github.com/Microsoft/go-winio/pkg/fs"
	"github.com/Microsoft/go-winio/pkg/guid"
	containerdtypes "github.com/containerd/containerd/api/types"
	"github.com/sirupsen/logrus"
)

// parseAndReserveLayers parses the container rootfs and layer folders into LCOW layers,
// then reserves SCSI slots for each read-only layer and the scratch layer.
//
// On partial failure the successfully reserved layers are still returned so the
// caller's top-level cleanup can release them.
func parseAndReserveLayers(
	ctx context.Context,
	vmID string,
	podID string,
	containerID string,
	layerFolders []string,
	rootfs []*containerdtypes.Mount,
	isScratchEncryptionEnabled bool,
	scsiReserver container.SCSIReserver,
) (*container.SCSILayerPlan, error) {

	log.G(ctx).WithFields(logrus.Fields{
		logfields.ContainerID: containerID,
		logfields.PodID:       podID,
	}).Trace("parsing and reserving LCOW layers")

	// Parse the rootfs mounts and layer folders into the canonical LCOW layer format.
	lcowLayers, err := layers.ParseLCOWLayers(rootfs, layerFolders)
	if err != nil {
		return nil, fmt.Errorf("parse lcow layers: %w", err)
	}

	// Create a layer plan to return.
	layerPlan := &container.SCSILayerPlan{}

	// Reserve a SCSI slot for each read-only layer.
	// The ordering is intentionally preserved so that Live Migration can
	// perform an exact replacement at the destination.
	for _, readonlyLayer := range lcowLayers.Layers {
		reservationID, layerGuestPath, err := reserveReadonlyLayer(ctx, scsiReserver, readonlyLayer)
		if err != nil {
			return layerPlan, fmt.Errorf("reserve readonly layer %s: %w", readonlyLayer.VHDPath, err)
		}

		layerPlan.ROLayers = append(layerPlan.ROLayers, container.MountReservation{
			ID:        reservationID,
			GuestPath: layerGuestPath,
		})
	}

	// Reserve a SCSI slot for the writable scratch layer.
	scratchReservationID, scratchMountPath, err := reserveScratchLayer(
		ctx, scsiReserver, vmID, lcowLayers.ScratchVHDPath, isScratchEncryptionEnabled,
	)
	if err != nil {
		return layerPlan, fmt.Errorf("reserve scratch layer %s: %w", lcowLayers.ScratchVHDPath, err)
	}

	// When sharing a scratch disk across multiple containers, derive a unique
	// sub-path per container to prevent upper/work directory collisions.
	scratchGuestPath := ospath.Join("linux", scratchMountPath, "scratch", podID, containerID)
	rootfsPath := ospath.Join("linux", guestpath.LCOWV2RootPrefixInVM, podID, containerID, guestpath.RootfsPath)

	layerPlan.Scratch = container.MountReservation{
		ID:        scratchReservationID,
		GuestPath: scratchGuestPath,
	}
	layerPlan.RootfsGuestPath = rootfsPath

	log.G(ctx).WithField("Plan", log.Format(ctx, layerPlan)).Trace("all LCOW layers reserved successfully")
	return layerPlan, nil
}

// reserveReadonlyLayer resolves the host path for a read-only layer and
// reserves a SCSI slot for it.
func reserveReadonlyLayer(
	ctx context.Context,
	scsiReserver container.SCSIReserver,
	layer *layers.LCOWLayer,
) (guid.GUID, string, error) {
	// Read-only layers come from the containerd snapshotter with broad read
	// permissions (typically via GrantVmGroupAccess), so no per-VM access
	// grant is needed here.

	hostPath, err := fs.ResolvePath(layer.VHDPath)
	if err != nil {
		return guid.GUID{}, "", fmt.Errorf("resolve symlinks for layer %s: %w", layer.VHDPath, err)
	}

	reservationID, guestPath, err := scsiReserver.Reserve(
		ctx,
		disk.Config{
			HostPath: hostPath,
			ReadOnly: true,
			Type:     disk.TypeVirtualDisk,
		},
		scsiMount.Config{
			Partition: layer.Partition,
			ReadOnly:  true,
			Options:   []string{"ro"},
		},
	)
	if err != nil {
		return guid.GUID{}, "", fmt.Errorf("reserve scsi slot for layer %s: %w", layer.VHDPath, err)
	}

	return reservationID, guestPath, nil
}

// reserveScratchLayer resolves the host path for the scratch VHD, grants VM
// access, and reserves a SCSI slot for it.
func reserveScratchLayer(
	ctx context.Context,
	scsiReserver container.SCSIReserver,
	vmID string,
	scratchVHDPath string,
	isScratchEncryptionEnabled bool,
) (guid.GUID, string, error) {
	// The scratch path may be a symlink to a shared sandbox.vhdx from another
	// container (e.g. the sandbox container). Resolve it before granting access.
	hostPath, err := fs.ResolvePath(scratchVHDPath)
	if err != nil {
		return guid.GUID{}, "", fmt.Errorf("resolve symlinks for scratch %s: %w", scratchVHDPath, err)
	}

	// Unlike read-only layers, the scratch VHD requires explicit per-VM access.
	if err = wclayer.GrantVmAccess(ctx, vmID, hostPath); err != nil {
		return guid.GUID{}, "", fmt.Errorf("grant vm access to scratch %s: %w", hostPath, err)
	}

	// Encrypted scratch disks use xfs; all others default to ext4.
	fileSystem := "ext4"
	if isScratchEncryptionEnabled {
		fileSystem = "xfs"
	}

	reservationID, guestPath, err := scsiReserver.Reserve(
		ctx,
		disk.Config{
			HostPath: hostPath,
			ReadOnly: false,
			Type:     disk.TypeVirtualDisk,
		},
		scsiMount.Config{
			Encrypted:        isScratchEncryptionEnabled,
			EnsureFilesystem: true,
			ReadOnly:         false,
			Filesystem:       fileSystem,
		},
	)
	if err != nil {
		return guid.GUID{}, "", fmt.Errorf("reserve scsi slot for scratch %s: %w", scratchVHDPath, err)
	}

	return reservationID, guestPath, nil
}
