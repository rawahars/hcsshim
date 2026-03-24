//go:build windows

package mount

// mountState represents the current state of a guest mount lifecycle.
//
// The normal progression is:
//
//	mountPending → mountMounted → mountUnmounted
//
// If mountInGuest fails, the owning goroutine moves the mount to
// mountInvalid and records the error. Other goroutines waiting on
// the same mount observe the invalid state and receive the original
// error. The entry is removed from the map immediately.
//
// Full state-transition table:
//
//	Current State        │ Trigger                            │ Next State
//	─────────────────────┼────────────────────────────────────┼────────────────────
//	mountPending         │ mountInGuest succeeds              │ mountMounted
//	mountPending         │ mountInGuest fails                 │ mountInvalid
//	mountMounted         │ unmountFromGuest succeeds          │ mountUnmounted
//	mountUnmounted       │ (terminal — no further transitions)│ —
//	mountInvalid         │ entry removed from map             │ —
type mountState int

const (
	// mountPending is the initial state; mountInGuest has been called but
	// has not yet completed.
	mountPending mountState = iota

	// mountMounted means mountInGuest succeeded; the path is accessible
	// inside the guest.
	mountMounted

	// mountUnmounted means unmountFromGuest succeeded; the guest path is
	// no longer accessible. This is a terminal state.
	mountUnmounted

	// mountInvalid means mountInGuest failed.
	mountInvalid
)

// String returns a human-readable name for the [mountState].
func (s mountState) String() string {
	switch s {
	case mountPending:
		return "Pending"
	case mountMounted:
		return "Mounted"
	case mountUnmounted:
		return "Unmounted"
	case mountInvalid:
		return "Invalid"
	default:
		return "Unknown"
	}
}
