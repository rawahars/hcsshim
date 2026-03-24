//go:build windows && wcow

package mount

import (
	"context"
	"errors"
	"fmt"

	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
)

// mountFmt is the guest path template for SCSI mounts on WCOW.
const mountFmt = `c:\mounts\scsi\m%d`

// mountInGuest mounts a SCSI disk into the Windows guest at the path specified by [SCSIMountConfig.GuestPath].
// Only controller 0 is supported; encrypted, partitioned, block-device, and filesystem-specific mounts are rejected.
func (m *Manager) mountInGuest(ctx context.Context, controller, lun uint, mountCfg *SCSIMountConfig) error {
	if controller != 0 {
		return errors.New("WCOW only supports SCSI controller 0")
	}

	if mountCfg.Encrypted || len(mountCfg.Options) != 0 ||
		mountCfg.EnsureFilesystem || mountCfg.Filesystem != "" || mountCfg.Partition != 0 || mountCfg.BlockDev {
		return errors.New("WCOW does not support encrypted, guest options, partitions, block devices, specifying mount filesystem, or ensuring filesystem on mounts")
	}

	settings := guestresource.WCOWMappedVirtualDisk{
		ContainerPath: mountCfg.GuestPath,
		Lun:           int32(lun),
	}

	var err error
	if mountCfg.FormatWithRefs {
		// FormatWithRefs signals the disk is a container scratch; use the dedicated API path.
		err = m.windowsGuestSCSI.AddWCOWMappedVirtualDiskForContainerScratch(ctx, settings)
	} else {
		err = m.windowsGuestSCSI.AddWCOWMappedVirtualDisk(ctx, settings)
	}
	if err != nil {
		return fmt.Errorf("add WCOW mapped virtual disk controller=%d lun=%d: %w", controller, lun, err)
	}
	return nil
}

// unmountFromGuest unmounts the SCSI disk identified by controller/lun from the Windows guest.
func (m *Manager) unmountFromGuest(ctx context.Context, controller, lun uint, mount *scsiMount) error {
	settings := guestresource.WCOWMappedVirtualDisk{
		ContainerPath: mount.guestPath,
		Lun:           int32(lun),
	}
	if err := m.windowsGuestSCSI.RemoveWCOWMappedVirtualDisk(ctx, settings); err != nil {
		return fmt.Errorf("remove WCOW mapped virtual disk controller=%d lun=%d path=%q: %w",
			controller, lun, mount.guestPath, err)
	}
	return nil
}
