//go:build windows && wcow

package scsi

import (
	"context"
	"errors"
	"fmt"

	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
)

// mountFmt is the guest path template for SCSI mounts on WCOW.
const mountFmt = `c:\mounts\scsi\m%d`

// mountInGuest mounts a SCSI disk into the Windows guest at the path stored
// in [mount.guestPath].
func (m *Manager) mountInGuest(ctx context.Context, controller, lun uint, mnt *mount) error {
	// Only controller 0 is supported on WCOW.
	if controller != 0 {
		return errors.New("WCOW only supports SCSI controller 0")
	}

	// Reject features not supported on WCOW.
	if mnt.config.Encrypted || len(mnt.config.Options) != 0 ||
		mnt.config.EnsureFilesystem || mnt.config.Filesystem != "" ||
		mnt.config.Partition != 0 || mnt.config.BlockDev {
		return errors.New("WCOW does not support encrypted, guest options, partitions, block devices, specifying mount filesystem, or ensuring filesystem on mounts")
	}

	settings := guestresource.WCOWMappedVirtualDisk{
		ContainerPath: mnt.guestPath,
		Lun:           int32(lun),
	}

	var err error
	if mnt.config.FormatWithRefs {
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

// unmountFromGuest unmounts the SCSI disk from the Windows guest.
func (m *Manager) unmountFromGuest(ctx context.Context, controller, lun uint, mnt *mount) error {
	settings := guestresource.WCOWMappedVirtualDisk{
		ContainerPath: mnt.guestPath,
		Lun:           int32(lun),
	}
	if err := m.windowsGuestSCSI.RemoveWCOWMappedVirtualDisk(ctx, settings); err != nil {
		return fmt.Errorf("remove WCOW mapped virtual disk controller=%d lun=%d path=%q: %w",
			controller, lun, mnt.guestPath, err)
	}
	return nil
}

// unplugFromGuest is a no-op on Windows guests.
func (m *Manager) unplugFromGuest(_ context.Context, _, _ uint) error {
	// Windows handles SCSI hot-unplug automatically when the host removes the disk from the VM.
	return nil
}
