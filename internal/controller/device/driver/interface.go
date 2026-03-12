//go:build windows

package driver

import "context"

// Controller manages kernel drivers within a running Utility VM.
type Controller interface {
	// Add mounts a share from the host into the UVM, installs any
	// kernel drivers in the share, and configures the environment
	// for library files and/or binaries in the share.
	//
	// `owner` is an identifier for the caller that owns this driver.
	// owner can be a specific container or the sandbox itself.
	//
	// `share` is a directory path on the host that contains files
	// for standard driver installation. For windows this means files
	// for pnp installation (.inf, .cat, .sys, .cert files).
	// For linux this means a vhd file that contains the drivers
	// under /lib/modules/`uname -r` for use with depmod and modprobe.
	Add(ctx context.Context, owner, share string) error

	// Remove unmounts a previously added driver from the UVM.
	// owner and share must match the values that were supplied to Add.
	Remove(ctx context.Context, owner, share string) error

	// List returns the host paths of all drivers currently installed in
	// the UVM that are owned by owner.
	List(ctx context.Context, owner string) ([]string, error)
}
