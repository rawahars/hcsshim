//go:build windows && !wcow

package mount

import (
	"context"
	"fmt"

	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
)

const mountFmt = "/run/mounts/scsi/m%d"

func (m *Manager) mountInGuest(ctx context.Context, controller, lun uint, mountCfg *MountConfig) error {
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
	if err := m.lcowGuest.AddLCOWMappedVirtualDisk(ctx, settings); err != nil {
		return fmt.Errorf("add LCOW mapped virtual disk controller=%d lun=%d: %w", controller, lun, err)
	}
	return nil
}

func (m *Manager) unmountFromGuest(ctx context.Context, controller, lun uint, gm *guestMount) error {
	settings := guestresource.LCOWMappedVirtualDisk{
		MountPath:  gm.guestPath,
		Controller: uint8(controller),
		Lun:        uint8(lun),
		ReadOnly:   gm.config.ReadOnly,
		Partition:  gm.config.Partition,
		BlockDev:   gm.config.BlockDev,
	}
	if err := m.lcowGuest.RemoveLCOWMappedVirtualDisk(ctx, settings); err != nil {
		return fmt.Errorf("remove LCOW mapped virtual disk controller=%d lun=%d path=%q: %w",
			controller, lun, gm.guestPath, err)
	}
	return nil
}
