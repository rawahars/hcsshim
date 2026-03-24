//go:build windows && !wcow

package mount

import (
	"context"
	"fmt"

	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
)

// mountFmt is the guest path template for SCSI mounts on LCOW.
const mountFmt = "/run/mounts/scsi/m%d"

// mountInGuest mounts a SCSI disk into the Linux guest at the path specified by [SCSIMountConfig.GuestPath].
func (m *Manager) mountInGuest(ctx context.Context, controller, lun uint, mountCfg *SCSIMountConfig) error {
	settings := guestresource.LCOWMappedVirtualDisk{
		MountPath:        mountCfg.GuestPath,
		Controller:       uint8(controller),
		Lun:              uint8(lun),
		Partition:        mountCfg.Partition,
		ReadOnly:         mountCfg.ReadOnly,
		Encrypted:        mountCfg.Encrypted,
		Options:          mountCfg.Options,
		EnsureFilesystem: mountCfg.EnsureFilesystem,
		Filesystem:       mountCfg.Filesystem,
		BlockDev:         mountCfg.BlockDev,
	}
	if err := m.linuxGuestSCSI.AddLCOWMappedVirtualDisk(ctx, settings); err != nil {
		return fmt.Errorf("add LCOW mapped virtual disk controller=%d lun=%d: %w", controller, lun, err)
	}
	return nil
}

// unmountFromGuest unmounts the SCSI disk identified by controller/lun from the Linux guest.
func (m *Manager) unmountFromGuest(ctx context.Context, controller, lun uint, mount *scsiMount) error {
	settings := guestresource.LCOWMappedVirtualDisk{
		MountPath:  mount.guestPath,
		Controller: uint8(controller),
		Lun:        uint8(lun),
		ReadOnly:   mount.config.ReadOnly,
		Partition:  mount.config.Partition,
		BlockDev:   mount.config.BlockDev,
	}
	if err := m.linuxGuestSCSI.RemoveLCOWMappedVirtualDisk(ctx, settings); err != nil {
		return fmt.Errorf("remove LCOW mapped virtual disk controller=%d lun=%d path=%q: %w",
			controller, lun, mount.guestPath, err)
	}
	return nil
}
