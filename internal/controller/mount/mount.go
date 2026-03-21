//go:build windows

package mount

// Manager tracks guest-level mounts and delegates to the appropriate
// OS-specific guest manager for the actual mount/unmount GCS calls.
type Manager struct {
	// mounts is the global index of every path currently mounted inside the
	// guest.  Key = resolved guestPath.
	// This is the authoritative source for deduplication: two callers
	// mounting the same disk at the same path share one guestMount entry and
	// jointly hold its refCount.
	mounts map[string]*guestMount

	// nextMountIdx is a monotonically increasing counter used to generate
	// stable unique guest paths when cfg.GuestPath is empty (see mountFmt).
	nextMountIdx int

	lcowGuest LCOWGuestMounter
	wcowGuest WCOWGuestMounter
}

var _ Controller = (*Manager)(nil)

// New creates a Manager that delegates mount operations to the given guest
// managers.  Pass nil for the guest type that is not applicable to the VM
// (e.g. nil wcowGuest for an LCOW VM).
func New(
	lcowGuest LCOWGuestMounter,
	wcowGuest WCOWGuestMounter,
) *Manager {
	return &Manager{
		mounts:    make(map[string]*guestMount),
		lcowGuest: lcowGuest,
		wcowGuest: wcowGuest,
	}
}
