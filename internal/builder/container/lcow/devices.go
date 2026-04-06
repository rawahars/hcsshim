//go:build windows && lcow

package lcow

import (
	"context"
	"fmt"

	"github.com/Microsoft/hcsshim/internal/builder/container"
	"github.com/Microsoft/hcsshim/internal/controller/device/vpci"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/logfields"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

// reserveAndUpdateDevices reserves vPCI devices on the host and updates each
// device's ID in the spec to the resulting VMBus channel GUID.
//
// On partial failure the successfully reserved IDs are still returned so the
// caller's top-level cleanup can release them.
func reserveAndUpdateDevices(
	ctx context.Context,
	vpciReserver container.VPCIReserver,
	specDevs []specs.WindowsDevice,
) ([]guid.GUID, error) {
	log.G(ctx).WithField("devices", log.Format(ctx, specDevs)).Trace("reserving vPCI devices")

	var reservations []guid.GUID

	for deviceIdx := range specDevs {
		device := &specDevs[deviceIdx]

		// Validate that the device type is supported before attempting reservation.
		if !vpci.IsValidDeviceType(device.IDType) {
			return reservations, fmt.Errorf("reserve device %s: unsupported type %s", device.ID, device.IDType)
		}

		// Parse the device path into a PCI ID and optional virtual function index.
		pciID, virtualFunctionIndex := vpci.GetDeviceInfoFromPath(device.ID)

		// Reserve the device on the host and obtain the VMBus channel GUID.
		vmBusGUID, err := vpciReserver.Reserve(ctx, vpci.Device{
			DeviceInstanceID:     pciID,
			VirtualFunctionIndex: virtualFunctionIndex,
		})
		if err != nil {
			return reservations, fmt.Errorf("reserve device %s: %w", device.ID, err)
		}

		log.G(ctx).WithFields(logrus.Fields{
			logfields.DeviceID:  pciID,
			logfields.VFIndex:   virtualFunctionIndex,
			logfields.VMBusGUID: vmBusGUID.String(),
		}).Trace("reserved vPCI device")

		// Update the spec entry so GCS references the VMBus GUID
		// instead of the original device path.
		device.ID = vmBusGUID.String()
		reservations = append(reservations, vmBusGUID)
	}

	log.G(ctx).Debug("all vPCI devices reserved successfully")

	return reservations, nil
}
