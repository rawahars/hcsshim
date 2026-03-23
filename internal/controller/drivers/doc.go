//go:build windows

// Package drivers provides utility methods for installing drivers into
// Linux or Windows utility VMs (UVMs).
//
// These utility methods are used by 'containerd-shim-runhcs-v1' as well as
// V2 shims to install the drivers.
//
// For LCOW guests, driver installation is performed by executing the
// 'install-drivers' binary inside the guest via [ExecGCSInstallDriver].
//
// For WCOW guests, driver installation is performed by invoking 'pnputil'
// inside the UVM via [ExecPnPInstallDriver].
package drivers
