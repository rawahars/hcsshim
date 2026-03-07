//go:build windows

package vm

// State represents the current state of the VM lifecycle.
// The VM progresses through states in the following order:
// StateNotCreated -> StateCreated -> StateRunning -> StateTerminated
type State int32

const (
	// StateNotCreated indicates the VM has not been created yet.
	// This is the initial state when a Controller is first instantiated.
	// Valid transitions: StateNotCreated -> StateCreated (via CreateVM)
	StateNotCreated State = iota

	// StateCreated indicates the VM has been created but not started.
	// Valid transitions: StateCreated -> StateRunning (via StartVM)
	StateCreated

	// StateRunning indicates the VM has been started and is running.
	// The guest OS is running and the Guest Compute Service (GCS) connection
	// is established.
	// Valid transitions: StateRunning -> StateTerminated (when VM exits or is terminated)
	StateRunning

	// StateTerminated indicates the VM has exited or been terminated.
	// This is a terminal state - once stopped, the VM cannot be restarted.
	// No further state transitions are possible.
	StateTerminated

	// StateInvalid is an invalid state, used to represent an error state.
	// When the VM is in this state, it indicates that an unrecoverable error has occurred.
	StateInvalid
)

// String returns a human-readable string representation of the VM State.
func (s State) String() string {
	switch s {
	case StateNotCreated:
		return "NotCreated"
	case StateCreated:
		return "Created"
	case StateRunning:
		return "Running"
	case StateTerminated:
		return "Terminated"
	case StateInvalid:
		return "Invalid"
	default:
		return "Unknown"
	}
}
