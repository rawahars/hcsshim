//go:build windows && lcow

package linuxcontainer

// State represents the current state of the container lifecycle.
// The container progresses through states in the following order:
// StateNotCreated -> StateCreated -> StateRunning -> StateStopped -> StateTerminated
type State int32

const (
	// StateNotCreated indicates the container has not been created yet.
	// This is the initial state when a Controller is first instantiated.
	// Valid transitions: StateNotCreated -> StateCreated (via Create)
	StateNotCreated State = iota

	// StateCreated indicates the container has been created but not started.
	// Valid transitions: StateCreated -> StateRunning (via Start)
	StateCreated

	// StateRunning indicates the container has been started and is running.
	// Valid transitions: StateRunning -> StateStopped (when the container's init process exits)
	StateRunning

	// StateStopped indicates the container's init process has exited.
	// Valid transitions: StateStopped -> StateTerminated (via Delete/cleanup)
	StateStopped

	// StateTerminated indicates the container has been fully cleaned up and terminated.
	// This is a terminal state - once terminated, the container cannot be restarted.
	// No further state transitions are possible.
	StateTerminated

	// StateInvalid is an invalid state, used to represent an error state.
	// When the container is in this state, it indicates that an unrecoverable error has occurred.
	StateInvalid
)

// String returns a human-readable string representation of the container State.
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
	case StateTerminated:
		return "Terminated"
	case StateInvalid:
		return "Invalid"
	default:
		return "Unknown"
	}
}
