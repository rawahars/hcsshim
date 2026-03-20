//go:build windows && !wcow

package scsi

import (
	"context"
	"fmt"

	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
)

// mountFmt is the guest path template for SCSI mounts on LCOW.
const mountFmt = "/run/mounts/scsi/m%d"

// mountInGuest mounts a SCSI disk partition into the Linux guest at the path
// stored in [mount.guestPath].
func (m *Manager) mountInGuest(ctx context.Context, controller, lun uint, mnt *mount) error {
	settings := guestresource.LCOWMappedVirtualDisk{
		MountPath:        mnt.guestPath,
		Controller:       uint8(controller),
		Lun:              uint8(lun),
		Partition:        mnt.config.Partition,
		ReadOnly:         mnt.config.ReadOnly,
		Encrypted:        mnt.config.Encrypted,
		Options:          mnt.config.Options,
		EnsureFilesystem: mnt.config.EnsureFilesystem,
		Filesystem:       mnt.config.Filesystem,
		BlockDev:         mnt.config.BlockDev,
	}
	if err := m.linuxGuestSCSI.AddLCOWMappedVirtualDisk(ctx, settings); err != nil {
		return fmt.Errorf("add LCOW mapped virtual disk controller=%d lun=%d: %w", controller, lun, err)
	}
	return nil
}

// unmountFromGuest unmounts the SCSI disk partition from the Linux guest.
func (m *Manager) unmountFromGuest(ctx context.Context, controller, lun uint, mnt *mount) error {
	settings := guestresource.LCOWMappedVirtualDisk{
		MountPath:  mnt.guestPath,
		Controller: uint8(controller),
		Lun:        uint8(lun),
		ReadOnly:   mnt.config.ReadOnly,
		Partition:  mnt.config.Partition,
		BlockDev:   mnt.config.BlockDev,
	}
	if err := m.linuxGuestSCSI.RemoveLCOWMappedVirtualDisk(ctx, settings); err != nil {
		return fmt.Errorf("remove LCOW mapped virtual disk controller=%d lun=%d path=%q: %w",
			controller, lun, mnt.guestPath, err)
	}
	return nil
}

// unplugFromGuest ejects a SCSI device from the Linux guest before the host
// removes it from the VM.
func (m *Manager) unplugFromGuest(ctx context.Context, controller, lun uint) error {
	settings := guestresource.SCSIDevice{
		Controller: uint8(controller),
		Lun:        uint8(lun),
	}

	// RemoveSCSIDevice sends a guest modification request that the GCS handles
	// by first remapping the logical controller number to the actual kernel-visible
	// controller index (HCS and the Linux kernel assign them independently), then
	// writing "1" to /sys/bus/scsi/devices/<id>/delete. That sysfs write is a
	// guest-initiated hot-unplug: the kernel removes the device from its bus and
	// flushes any in-flight I/O before the host removes the disk from the VM.
	if err := m.linuxGuestSCSI.RemoveSCSIDevice(ctx, settings); err != nil {
		return fmt.Errorf("remove scsi device at controller=%d lun=%d from lcow guest: %w", controller, lun, err)
	}
	return nil
}
