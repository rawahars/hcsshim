//go:build windows && (lcow || wcow)

// Package process provides a controller for managing individual process
// (exec) instances within a container. It handles the full lifecycle from
// creation through exit, including IO plumbing, signal delivery, and exit
// status reporting. A live-migration entry point is provided via [Import]
// (state-only rehydration) and [Controller.Resume] (binds the live hosting
// system / process handle once the destination is ready).
//
// # Lifecycle
//
// A controller created via [New] follows the live-creation path:
//
//	┌───────────────────┐
//	│  StateNotCreated  │
//	└────────┬──────────┘
//	         │ Create
//	         ▼
//	┌───────────────────┐
//	│   StateCreated    │── Start fails / Kill / Delete──┐
//	└────────┬──────────┘                                │
//	         │ Start ok                                  │
//	         ▼                                           │
//	┌───────────────────┐                                │
//	│   StateRunning    │──── process exits / Kill ──────┤
//	└───────────────────┘                                │
//	                                                     ▼
//	                                           ┌───────────────────┐
//	                                           │  StateTerminated  │
//	                                           └───────────────────┘
//
// A controller rehydrated via [Import] enters the migration branch instead,
// and rejoins the live-creation states only after [Controller.Resume]:
//
//	┌────────────────┐  Resume(next)   ┌──────────────────────────────┐
//	│ StateMigrating │ ───────────────▶│ caller-supplied next state   │
//	└────────────────┘                 └──────────────────────────────┘
//
//	  - [Controller.Create] sets up upstream IO connections and stores the
//	    process spec. The controller transitions from StateNotCreated to
//	    StateCreated.
//	  - [Controller.Start] launches the process inside the hosting system
//	    and spawns a background goroutine to monitor exit. The controller
//	    transitions from StateCreated to StateRunning.
//	  - [Controller.Kill] delivers a signal to a running process or
//	    terminates a created-but-not-started process.
//	  - [Controller.Delete] prepares the process for removal from the
//	    container's process table. For a created-but-never-started process,
//	    it transitions to StateTerminated and releases its IO resources.
//	  - [Controller.Wait] blocks until the process exits or the context
//	    is cancelled.
//	  - [Controller.Status] returns the current containerd-compatible state
//	    of the process.
//
// # Exit Handling
//
// When a process is started, a background goroutine waits for the process
// to exit, records the exit code and timestamp, drains all IO copies, and
// publishes a TaskExit event via the caller-supplied channel. The
// exitedCh channel is closed once all cleanup is complete, unblocking any
// [Controller.Wait] callers.
package process
