//go:build windows && wcow

package mount

import (
	"context"
	"errors"
	"fmt"

	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
)

const mountFmt = `c:\mounts\scsi\m%d`

func (m *Manager) mountInGuest(ctx context.Context, controller, lun uint, mountCfg *MountConfig) error {
	if controller != 0 {
		return errors.New("WCOW only supports SCSI controller 0")
	}
	if mountCfg.Encrypted || len(mountCfg.Options) != 0 ||
		mountCfg.EnsureFilesystem || mountCfg.Filesystem != "" || mountCfg.Partition != 0 {
		return errors.New("WCOW does not support encrypted, verity, guest options, partitions, specifying mount filesystem, or ensuring filesystem on mounts")
	}

	settings := guestresource.WCOWMappedVirtualDisk{
		ContainerPath: mountCfg.GuestPath,
		Lun:           int32(lun),
	}

	var err error
	if mountCfg.FormatWithRefs {
		err = m.wcowGuest.AddWCOWMappedVirtualDiskForContainerScratch(ctx, settings)
	} else {
		err = m.wcowGuest.AddWCOWMappedVirtualDisk(ctx, settings)
	}
	if err != nil {
		return fmt.Errorf("add WCOW mapped virtual disk controller=%d lun=%d: %w", controller, lun, err)
	}
	return nil
}

func (m *Manager) unmountFromGuest(ctx context.Context, controller, lun uint, gm *guestMount) error {
	settings := guestresource.WCOWMappedVirtualDisk{
		ContainerPath: gm.guestPath,
		Lun:           int32(lun),
	}
	if err := m.wcowGuest.RemoveWCOWMappedVirtualDisk(ctx, settings); err != nil {
		return fmt.Errorf("remove WCOW mapped virtual disk controller=%d lun=%d path=%q: %w",
			controller, lun, gm.guestPath, err)
	}
	return nil
}
