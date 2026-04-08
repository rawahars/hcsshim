//go:build windows

package process

import (
	containerdtypes "github.com/containerd/containerd/api/types/task"
)

// State represents the current state of the process lifecycle.
// The process progresses through states in the following order:
// StateNotCreated -> StateCreated -> StateRunning -> StateTerminated
type State int32

const (
	// StateNotCreated indicates the process has not been created yet.
	// This is the initial state when a process controller is first instantiated.
	// Valid transitions: StateNotCreated -> StateCreated (via Create)
	StateNotCreated State = iota

	// StateCreated indicates the process has been created but not started.
	// Valid transitions: StateCreated -> StateRunning (via Start)
	StateCreated

	// StateRunning indicates the process has been started and is running.
	// Valid transitions: StateRunning -> StateTerminated (when the process exits)
	StateRunning

	// StateTerminated indicates the process has exited and been fully cleaned up.
	// This is a terminal state - once terminated, the process cannot be restarted.
	// No further state transitions are possible.
	StateTerminated

	// StateInvalid is an invalid state, used to represent an error state.
	// When the process is in this state, it indicates that an unrecoverable error has occurred.
	StateInvalid
)

// String returns a human-readable string representation of the process State.
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

// ContainerdStatus converts the process State into the equivalent containerd task Status.
// StateNotCreated and StateInvalid map to Status_UNKNOWN, as they have no direct
// containerd equivalent.
func (s State) ContainerdStatus() containerdtypes.Status {
	switch s {
	case StateCreated:
		return containerdtypes.Status_CREATED
	case StateRunning:
		return containerdtypes.Status_RUNNING
	case StateTerminated:
		return containerdtypes.Status_STOPPED
	default:
		// StateNotCreated and StateInvalid have no direct containerd equivalent.
		return containerdtypes.Status_UNKNOWN
	}
}
