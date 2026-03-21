//go:build windows

package mount

import "fmt"

// mountState tracks the lifecycle position of a guestMount.
//
// Valid transitions (forward-only):
//
//	(none) ─ mountInGuest ──► mountMounted
//	mountMounted ─ unmountFromGuest ──► mountUnmounted
type mountState int

const (
	// mountMounted means mountInGuest succeeded; the disk is mounted and
	// accessible at guestPath inside the guest.
	mountMounted mountState = iota

	// mountUnmounted means unmountFromGuest succeeded; the guest path is no
	// longer accessible.  The guestMount should be deleted from the map
	// immediately after entering this state.
	mountUnmounted
)

func (s mountState) String() string {
	switch s {
	case mountMounted:
		return "Mounted"
	case mountUnmounted:
		return "Unmounted"
	default:
		return fmt.Sprintf("mountState(%d)", int(s))
	}
}
