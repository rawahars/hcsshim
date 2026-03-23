//go:build windows
// +build windows

package devices

import (
	"context"
	"fmt"

	"github.com/Microsoft/hcsshim/internal/controller/drivers"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/resources"
	"github.com/Microsoft/hcsshim/internal/uvm"
	"github.com/Microsoft/hcsshim/internal/uvm/scsi"
)

// InstallDrivers mounts a share from the host into the UVM, installs any kernel drivers in the share,
// and configures the environment for library files and/or binaries in the share.
//
// InstallDrivers mounts a specified kernel driver, then installs it in the UVM.
//
// `share` is a directory path on the host that contains files for standard driver installation.
// For windows this means files for pnp installation (.inf, .cat, .sys, .cert files).
// For linux this means a vhd file that contains the drivers under /lib/modules/`uname -r` for use
// with depmod and modprobe.
//
// Returns a ResourceCloser for the added mount. On failure, the mounted share will be released,
// the returned ResourceCloser will be nil, and an error will be returned.
func InstallDrivers(ctx context.Context, vm *uvm.UtilityVM, share string) (closer resources.ResourceCloser, err error) {
	defer func() {
		if err != nil && closer != nil {
			// best effort clean up allocated resource on failure
			if releaseErr := closer.Release(ctx); releaseErr != nil {
				log.G(ctx).WithError(releaseErr).Error("failed to release container resource")
			}
			closer = nil
		}
	}()
	if vm.OS() == "windows" {
		options := vm.DefaultVSMBOptions(true)
		closer, err = vm.AddVSMB(ctx, share, options)
		if err != nil {
			return closer, fmt.Errorf("failed to add VSMB share to utility VM for path %+v: %w", share, err)
		}
		uvmPath, err := vm.GetVSMBUvmPath(ctx, share, true)
		if err != nil {
			return closer, err
		}
		// attempt to install even if the driver has already been installed before so we
		// can guarantee the device is ready for use afterwards
		return closer, drivers.ExecPnPInstallDriver(ctx, vm, uvmPath)
	}

	// first mount driver as scsi in standard mount location
	mount, err := vm.SCSIManager.AddVirtualDisk(
		ctx,
		share,
		true,
		vm.ID(),
		"",
		&scsi.MountConfig{},
	)
	if err != nil {
		return closer, fmt.Errorf("failed to add SCSI disk to utility VM for path %+v: %w", share, err)
	}
	closer = mount
	uvmPathForShare := mount.GuestPath()

	// install drivers using gcs tool `install-drivers`
	return closer, drivers.ExecGCSInstallDriver(ctx, vm, share, uvmPathForShare)
}
