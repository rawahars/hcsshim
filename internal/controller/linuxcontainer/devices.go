//go:build windows && lcow

package linuxcontainer

import (
	"context"
	"fmt"

	"github.com/Microsoft/hcsshim/internal/controller/device/vpci"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/logfields"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

// allocateDevices reserves and maps vPCI devices for the container,
// rewriting each device's ID in the spec to the resulting VMBus channel GUID.
func (c *Controller) allocateDevices(ctx context.Context, spec *specs.Spec) error {
	log.G(ctx).WithField("devices", log.Format(ctx, spec.Windows.Devices)).Trace("reserving vPCI devices")

	for idx := range spec.Windows.Devices {
		device := &spec.Windows.Devices[idx]

		// Validate that the device type is supported before attempting reservation.
		if !vpci.IsValidDeviceType(device.IDType) {
			return fmt.Errorf("reserve device %s: unsupported type %s", device.ID, device.IDType)
		}

		// Parse the device path into a PCI ID and optional virtual function index.
		pciID, virtualFunctionIndex := vpci.GetDeviceInfoFromPath(device.ID)

		// Reserve the device on the host.
		vmBusGUID, err := c.vpci.Reserve(ctx, vpci.Device{
			DeviceInstanceID:     pciID,
			VirtualFunctionIndex: virtualFunctionIndex,
		})
		if err != nil {
			return fmt.Errorf("reserve device %s: %w", device.ID, err)
		}

		// Map the device into the VM.
		if err = c.vpci.AddToVM(ctx, vmBusGUID); err != nil {
			return fmt.Errorf("add device %s to vm: %w", device.ID, err)
		}

		log.G(ctx).WithFields(logrus.Fields{
			logfields.DeviceID:  pciID,
			logfields.VFIndex:   virtualFunctionIndex,
			logfields.VMBusGUID: vmBusGUID.String(),
		}).Trace("reserved and mapped vPCI device")

		// Rewrite the spec entry so GCS references the VMBus GUID.
		device.ID = vmBusGUID.String()
		c.devices = append(c.devices, vmBusGUID)
	}

	log.G(ctx).Debug("all vPCI devices allocated successfully")
	return nil
}
