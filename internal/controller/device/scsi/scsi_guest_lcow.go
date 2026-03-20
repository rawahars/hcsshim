//go:build windows && !wcow

package scsi

import (
	"context"
	"fmt"

	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
)

// unplugFromGuest ejects the SCSI device at (controller, lun) from the Linux guest
// before the host removes it from the VM.
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
	if err := m.linuxGuestMgr.RemoveSCSIDevice(ctx, settings); err != nil {
		return fmt.Errorf("remove scsi device at controller=%d lun=%d from lcow guest: %w", controller, lun, err)
	}
	return nil
}
