//go:build windows && lcow

package lcow

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Microsoft/hcsshim/internal/builder/container"
	plan9Mount "github.com/Microsoft/hcsshim/internal/controller/device/plan9/mount"
	"github.com/Microsoft/hcsshim/internal/controller/device/plan9/share"
	"github.com/Microsoft/hcsshim/internal/controller/device/scsi/disk"
	scsiMount "github.com/Microsoft/hcsshim/internal/controller/device/scsi/mount"
	"github.com/Microsoft/hcsshim/internal/guestpath"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/wclayer"

	"github.com/Microsoft/go-winio/pkg/fs"
	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/opencontainers/runtime-spec/specs-go"
)

// Mount type constants.
const (
	// mountTypeBind is a regular host-directory bind mount served via a Plan9 share.
	mountTypeBind = "bind"

	// mountTypePhysicalDisk hot-adds a physical pass-through disk via the SCSI controller.
	mountTypePhysicalDisk = "physical-disk"

	// mountTypeVirtualDisk hot-adds a VHD or VHDX via the SCSI controller.
	mountTypeVirtualDisk = "virtual-disk"

	// mountTypeExtensibleVirtualDisk hot-adds an extensible virtual disk via the SCSI controller.
	mountTypeExtensibleVirtualDisk = "extensible-virtual-disk"

	// mountTypeNone signals that the mount is a disk-backed device mount whose
	// filesystem will be resolved when the guest actually mounts the device.
	mountTypeNone = "none"
)

// reserveAndUpdateMounts reserves host-side resources for each OCI mount and
// rewrites mount sources to their guest-visible paths.
//
// On partial failure the successfully reserved IDs are still returned so the
// caller's top-level cleanup can release them.
func reserveAndUpdateMounts(
	ctx context.Context,
	vmID string,
	scsiReserver container.SCSIReserver,
	plan9Reserver container.Plan9Reserver,
	mounts []specs.Mount,
) ([]guid.GUID, []guid.GUID, error) {
	var scsiReservations, plan9Reservations []guid.GUID

	for idx := range mounts {
		log.G(ctx).WithField("mount", log.Format(ctx, mounts[idx])).Trace("processing OCI mount")
		mount := &mounts[idx]

		// Validate that every mount has the minimum required fields.
		if mount.Destination == "" || mount.Source == "" {
			return scsiReservations, plan9Reservations, fmt.Errorf("invalid mount: both source and destination are required: %+v", mount)
		}

		// Check if the mount is read-only.
		isReadOnly := isReadOnlyMount(mount)

		// Dispatch to a mount-type-specific handler.
		switch mount.Type {
		case mountTypeVirtualDisk, mountTypePhysicalDisk, mountTypeExtensibleVirtualDisk:
			reservationID, err := reserveSCSIMount(ctx, vmID, scsiReserver, mount, isReadOnly)
			if err != nil {
				return scsiReservations, plan9Reservations, err
			}

			scsiReservations = append(scsiReservations, reservationID)

		case mountTypeBind:
			// Hugepages mounts are backed by a pre-existing mount inside the UVM;
			// only validate the path format and move on.
			if strings.HasPrefix(mount.Source, guestpath.HugePagesMountPrefix) {
				if err := validateHugePageMount(mount.Source); err != nil {
					return scsiReservations, plan9Reservations, err
				}
				continue
			}

			// Guest-internal paths (sandbox://, sandbox-tmp://, uvm://) resolve
			// entirely inside the UVM and require no host-side reservation.
			if isGuestInternalPath(mount.Source) {
				continue
			}

			// All remaining bind mounts are host directories served via Plan9 for Linux guests.
			reservationID, err := reservePlan9Mount(ctx, plan9Reserver, mount, isReadOnly)
			if err != nil {
				return scsiReservations, plan9Reservations, err
			}
			plan9Reservations = append(plan9Reservations, reservationID)

		default:
			// Unknown mount types (e.g. tmpfs, devpts, proc) are passed through
			// to the guest without host-side resource reservation.
		}
	}

	log.G(ctx).Debug("all OCI mounts reserved successfully")
	return scsiReservations, plan9Reservations, nil
}

// --- SCSI mounts (virtual-disk / physical-disk / extensible-virtual-disk) ---

// reserveSCSIMount resolves the host path, optionally grants VM access, and
// reserves a SCSI slot for any disk-backed mount type.
func reserveSCSIMount(
	ctx context.Context,
	vmID string,
	scsiReserver container.SCSIReserver,
	mount *specs.Mount,
	isReadOnly bool,
) (guid.GUID, error) {
	// Build the disk config based on mount type. Each branch resolves the
	// host path and sets the appropriate disk type.
	var diskConfig disk.Config
	switch mount.Type {
	case mountTypeVirtualDisk, mountTypePhysicalDisk:
		// Resolve any symlinks to get the real host path for the disk.
		hostPath, err := fs.ResolvePath(mount.Source)
		if err != nil {
			return guid.GUID{}, fmt.Errorf("resolve symlinks for mount source %s: %w", mount.Source, err)
		}

		// The VM needs explicit access to the disk before it can be attached.
		if err = wclayer.GrantVmAccess(ctx, vmID, hostPath); err != nil {
			return guid.GUID{}, fmt.Errorf("grant vm access to %s: %w", hostPath, err)
		}

		// Physical disks use pass-through; everything else is a virtual disk.
		diskType := disk.TypeVirtualDisk
		if mount.Type == mountTypePhysicalDisk {
			diskType = disk.TypePassThru
		}

		// Create the final disk config.
		diskConfig = disk.Config{HostPath: hostPath, ReadOnly: isReadOnly, Type: diskType}

	case mountTypeExtensibleVirtualDisk:
		// EVD paths encode the provider type in the source URI.
		evdType, sourcePath, err := parseExtensibleVirtualDiskPath(mount.Source)
		if err != nil {
			return guid.GUID{}, fmt.Errorf("parse extensible virtual disk path: %w", err)
		}

		// Resolve any symlinks to get the real host path for the disk.
		hostPath, err := fs.ResolvePath(sourcePath)
		if err != nil {
			return guid.GUID{}, fmt.Errorf("resolve symlinks for mount source %s: %w", sourcePath, err)
		}

		// Create the final disk config.
		diskConfig = disk.Config{HostPath: hostPath, ReadOnly: isReadOnly, Type: disk.TypeExtensibleVirtualDisk, EVDType: evdType}

	default:
		return guid.GUID{}, fmt.Errorf("unsupported scsi mount type %q", mount.Type)
	}

	// Check if this was a block dev mount.
	isBlockDev := strings.HasPrefix(mount.Destination, guestpath.BlockDevMountPrefix)

	// Reserve the mount.
	reservationID, guestPath, err := scsiReserver.Reserve(
		ctx,
		diskConfig,
		scsiMount.Config{
			ReadOnly: isReadOnly,
			Options:  mount.Options,
			BlockDev: isBlockDev,
		},
	)
	if err != nil {
		return guid.GUID{}, fmt.Errorf("reserve scsi mount for %+v: %w", mount, err)
	}

	// Rewrite the mount source to the guest-visible path and clear the type
	// so the guest resolves the filesystem. Block-device mounts retain bind type.
	mount.Source = guestPath
	mount.Type = mountTypeNone
	if isBlockDev {
		mount.Type = mountTypeBind
	}

	return reservationID, nil
}

// parseExtensibleVirtualDiskPath extracts the EVD type and source path from an
// extensible virtual disk host path with the format "evd://<type>/<path>".
func parseExtensibleVirtualDiskPath(hostPath string) (evdType, sourcePath string, err error) {
	const evdPrefix = "evd://"

	if !strings.HasPrefix(hostPath, evdPrefix) {
		return "", "", fmt.Errorf("invalid extensible virtual disk path %q: missing %q prefix", hostPath, evdPrefix)
	}

	trimmedPath := strings.TrimPrefix(hostPath, evdPrefix)
	separatorIdx := strings.Index(trimmedPath, "/")
	if separatorIdx <= 0 {
		return "", "", fmt.Errorf("invalid extensible virtual disk path %q: expected format %s<type>/<path>", hostPath, evdPrefix)
	}

	return trimmedPath[:separatorIdx], trimmedPath[separatorIdx+1:], nil
}

// --- Bind mounts (Plan9 shares, hugepages, guest-internal paths) ---

// validateHugePageMount checks that a hugepages mount source has the expected
// format and a supported page size.
func validateHugePageMount(source string) error {
	// Expected format: "hugepages://<size>/<location>"
	hugePageSubDirs := strings.Split(strings.TrimPrefix(source, guestpath.HugePagesMountPrefix), "/")
	if len(hugePageSubDirs) < 2 {
		return fmt.Errorf(
			"invalid hugepages mount path %s: expected format %s<size>/<location>",
			source,
			guestpath.HugePagesMountPrefix,
		)
	}

	// Only 2M (megabyte) hugepages are currently supported.
	if hugePageSubDirs[0] != "2M" {
		return fmt.Errorf("unsupported hugepage size %s: only 2M is supported", hugePageSubDirs[0])
	}

	return nil
}

// reservePlan9Mount reserves a Plan9 share for a host-backed bind mount,
// restricting to a single file when the source is not a directory.
func reservePlan9Mount(
	ctx context.Context,
	plan9Reserver container.Plan9Reserver,
	mount *specs.Mount,
	isReadOnly bool,
) (guid.GUID, error) {
	// Ensure that mount source exists.
	fileInfo, err := os.Stat(mount.Source)
	if err != nil {
		return guid.GUID{}, fmt.Errorf("stat bind mount source %s: %w", mount.Source, err)
	}

	shareConfig := share.Config{
		HostPath: mount.Source,
		ReadOnly: isReadOnly,
	}

	// For single-file mounts, share the containing directory but restrict
	// access to the specific file.
	if !fileInfo.IsDir() {
		hostDir, fileName := filepath.Split(mount.Source)
		shareConfig.HostPath = hostDir
		shareConfig.Restrict = true
		shareConfig.AllowedNames = append(shareConfig.AllowedNames, fileName)
	}

	// Reserve the plan9 share.
	reservationID, guestPath, err := plan9Reserver.Reserve(ctx, shareConfig, plan9Mount.Config{ReadOnly: isReadOnly})
	if err != nil {
		return guid.GUID{}, fmt.Errorf("reserve plan9 share for mount %+v: %w", mount, err)
	}

	// Rewrite the mount source to the guest-visible path.
	mount.Source = guestPath
	return reservationID, nil
}

// --- Helpers ---

// isReadOnlyMount returns true if the mount options contain the "ro" flag.
func isReadOnlyMount(mount *specs.Mount) bool {
	for _, option := range mount.Options {
		if strings.EqualFold(option, "ro") {
			return true
		}
	}
	return false
}

// isGuestInternalPath reports whether the path uses a UVM-internal prefix
// that resolves inside the guest.
func isGuestInternalPath(path string) bool {
	// Mounts that map to a path in UVM are specified with a 'sandbox://', 'sandbox-tmp://', or 'uvm://' prefix.
	// examples:
	//  - sandbox:///a/dirInUvm destination:/b/dirInContainer
	//  - sandbox-tmp:///a/dirInUvm destination:/b/dirInContainer
	//  - uvm:///a/dirInUvm destination:/b/dirInContainer
	return strings.HasPrefix(path, guestpath.SandboxMountPrefix) ||
		strings.HasPrefix(path, guestpath.SandboxTmpfsMountPrefix) ||
		strings.HasPrefix(path, guestpath.UVMMountPrefix)
}
