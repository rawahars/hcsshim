//go:build windows

package mount

import "sync"

// Manager tracks guest-level mounts for SCSI and Plan9 devices, and delegates
// to the appropriate OS-specific guest manager for the actual GCS calls.
type Manager struct {
	// globalMu protects the scsiMounts and plan9Mounts maps and serializes
	// path allocation across concurrent callers.
	globalMu sync.Mutex

	// scsiMounts is the global index of SCSI mounts. Key = resolved guestPath.
	// Two callers mounting the same disk at the same path share one scsiMount
	// entry and jointly hold its refCount.
	scsiMounts map[string]*scsiMount

	// plan9Mounts is the global index of Plan9 mounts. Key = resolved guestPath.
	plan9Mounts map[string]*plan9Mount

	// nextSCSIMountIdx generates stable unique guest paths for SCSI auto-paths.
	nextSCSIMountIdx int

	// nextPlan9MountIdx generates stable unique guest paths for Plan9 auto-paths.
	nextPlan9MountIdx int

	// Interfaces used for performing guest actions.
	linuxGuestSCSI   linuxGuestSCSI
	windowsGuestSCSI windowsGuestSCSI
	linuxGuestPlan9  linuxGuestPlan9
}

// New creates a new instance of mount.Manager which can be used
// for perform SCSI and Plan9 mount operations.
func New(
	linuxGuestSCSI linuxGuestSCSI,
	windowsGuestSCSI windowsGuestSCSI,
	linuxGuestPlan9 linuxGuestPlan9,
) *Manager {
	return &Manager{
		scsiMounts:       make(map[string]*scsiMount),
		plan9Mounts:      make(map[string]*plan9Mount),
		linuxGuestSCSI:   linuxGuestSCSI,
		windowsGuestSCSI: windowsGuestSCSI,
		linuxGuestPlan9:  linuxGuestPlan9,
	}
}
