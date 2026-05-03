//go:build windows && (lcow || wcow)

package process

import (
	containerdtypes "github.com/containerd/containerd/api/types/task"
)

// State represents the current state of the process lifecycle.
//
// The normal progression is:
//
//	StateNotCreated → StateCreated → StateRunning → StateTerminated
//
// On the destination side of a live migration, the controller is rehydrated
// via [Import] directly into [StateMigrating] and only rejoins the table
// above once [Controller.Resume] supplies the live hosting system / process
// handle and the caller-supplied next state.
//
// Full state-transition table:
//
//	Current State    │ Trigger                              │ Next State
//	─────────────────┼──────────────────────────────────────┼────────────────
//	StateNotCreated  │ Create succeeds                      │ StateCreated
//	StateCreated     │ Start succeeds                       │ StateRunning
//	StateCreated     │ Start fails / Kill / Delete          │ StateTerminated
//	StateRunning     │ process exits                        │ StateTerminated
//	StateRunning     │ Kill succeeds (signal or terminate)  │ StateTerminated
//	StateTerminated  │ (terminal — no further transitions)  │ —
//	StateMigrating   │ Resume(next)                         │ next
type State int32

const (
	// StateNotCreated indicates the process has not been created yet.
	// This is the initial state set by [New].
	StateNotCreated State = iota

	// StateCreated indicates the process has been created but not started.
	// IO connections are established and the process spec is stored.
	StateCreated

	// StateRunning indicates the process has been started and is executing.
	StateRunning

	// StateTerminated indicates the process has exited and all cleanup is done.
	// This is a terminal state — no further transitions are possible.
	StateTerminated

	// StateMigrating indicates the controller has been rehydrated from a
	// migration snapshot via [Import] but has not yet been bound to a live
	// hosting system / process handle. [Controller.Resume] moves
	// the controller out of [StateMigrating] into the caller-supplied next
	// state.
	StateMigrating
)

// String returns a human-readable representation of the State.
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
	case StateMigrating:
		return "Migrating"
	default:
		return "Unknown"
	}
}

// ContainerdStatus converts the State into the equivalent containerd task Status.
func (s State) ContainerdStatus() containerdtypes.Status {
	switch s {
	case StateCreated:
		return containerdtypes.Status_CREATED
	case StateRunning:
		return containerdtypes.Status_RUNNING
	case StateTerminated:
		return containerdtypes.Status_STOPPED
	default:
		// StateNotCreated and StateMigrating have no direct containerd equivalent.
		return containerdtypes.Status_UNKNOWN
	}
}
