//go:build windows && lcow

package linuxcontainer

// State represents the current lifecycle state of the container.
//
// Normal progression:
//
//	StateNotCreated → StateCreated → StateRunning → StateStopped
//
// On the destination side of a live migration, the controller is rehydrated
// via [Import] directly into [StateMigrating] and only rejoins the table
// above once [Controller.Resume] supplies the live VM/guest dependencies
// and the caller-supplied next state.
//
// Full state-transition table:
//
//	Current State    │ Trigger                                          │ Next State
//	─────────────────┼──────────────────────────────────────────────────┼────────────────
//	StateNotCreated  │ Create succeeds                                  │ StateCreated
//	StateNotCreated  │ Create fails during resource allocation or later │ StateInvalid
//	StateCreated     │ Start succeeds                                   │ StateRunning
//	StateCreated     │ Start fails                                      │ StateInvalid
//	StateRunning     │ init process exits                               │ StateStopped
//	StateStopped     │ (terminal — no further transitions)              │ —
//	StateInvalid     │ (terminal — no further transitions)              │ —
//	StateMigrating   │ Resume(next)                                     │ next
type State int32

const (
	// StateNotCreated indicates the container has not been created yet.
	StateNotCreated State = iota

	// StateCreated indicates the container has been created but not started.
	StateCreated

	// StateRunning indicates the container has been started and is running.
	StateRunning

	// StateStopped indicates the container's init process has exited and
	// all host-side resources have been released.
	StateStopped

	// StateInvalid indicates the container entered an unrecoverable failure
	// during Create or Start.
	StateInvalid

	// StateMigrating indicates the controller has been rehydrated from a
	// migration snapshot via [Import] but has not yet been bound to the
	// live VM, GCS guest, and device controllers. [Controller.Resume]
	// moves the controller out of [StateMigrating] into the caller-supplied
	// next state.
	StateMigrating
)

// String returns a human-readable representation of the container State.
func (s State) String() string {
	switch s {
	case StateNotCreated:
		return "NotCreated"
	case StateCreated:
		return "Created"
	case StateRunning:
		return "Running"
	case StateStopped:
		return "Stopped"
	case StateInvalid:
		return "Invalid"
	case StateMigrating:
		return "Migrating"
	default:
		return "Unknown"
	}
}
