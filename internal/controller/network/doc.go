//go:build windows && (lcow || wcow)

// Package network provides a controller for managing the network lifecycle of a pod
// running inside a Utility VM (UVM).
//
// It handles attaching an HCN namespace and its endpoints to the guest VM,
// and tearing them down on pod removal. A live-migration entry point is
// provided via [Import] (state-only rehydration) and [Controller.Resume]
// (binds host/guest interfaces once the destination VM is running).
//
// # Lifecycle
//
// A network controller created via [New] follows the live-creation path:
//
//	       ┌────────────────────┐
//	       │ StateNotConfigured │
//	       └───┬────────────┬───┘
//	Setup ok   │            │ Setup fails
//	           ▼            ▼
//	┌─────────────────┐  ┌──────────────┐
//	│ StateConfigured │  │ StateInvalid │
//	└────────┬────────┘  └──────┬───────┘
//	         │ Teardown         │ Teardown
//	         ▼                  ▼
//	┌─────────────────────────────────────┐
//	│           StateTornDown             │
//	└─────────────────────────────────────┘
//
// A controller rehydrated via [Import] enters the migration branch instead,
// and rejoins the live-creation states only after [Controller.Resume]:
//
//	┌────────────────┐  Resume(next)   ┌──────────────────────────────┐
//	│ StateMigrating │ ───────────────▶│ caller-supplied next state   │
//	└────────────────┘                 └──────────────────────────────┘
//
// State descriptions:
//
//   - [StateNotConfigured]: initial state; no namespace or NICs have been configured.
//   - [StateConfigured]: after [Controller.Setup] succeeds; the HCN namespace is attached
//     and all endpoints are wired up inside the guest.
//   - [StateInvalid]: entered when [Controller.Setup] fails mid-way; best-effort
//     cleanup should be performed via [Controller.Teardown].
//   - [StateTornDown]: terminal state reached after [Controller.Teardown]
//     completes.
//   - [StateMigrating]: initial state for [Import]; host/guest interfaces are
//     not yet bound. All operational APIs (Setup, Teardown, NIC add/remove)
//     reject calls until [Controller.Resume] supplies the live interfaces and
//     the next state.
//
// # Platform Variants
//
// Guest-side operations differ between LCOW and WCOW and are implemented in
// platform-specific source files selected via build tags
// ("lcow" tag for LCOW shim, "wcow" tag for WCOW shim).
package network
