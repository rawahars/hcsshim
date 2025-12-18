//go:build windows

package main

import (
	"github.com/Microsoft/hcsshim/internal/uvm"
	"github.com/containerd/platforms"
)

// sandboxState tracks the lifecycle and configuration of a
// sandbox managed by the shim via Sandbox APIs.
type sandboxState struct {
	// id is the unique identifier for the sandbox.
	// This MUST remain constant for the lifetime of the sandbox.
	id string

	platform *platforms.Platform

	// Options for building a UVM.
	lcowOptions *uvm.OptionsLCOW
	wcowOptions *uvm.OptionsWCOW

	// host is the UtilityVM instance backing the sandbox when isolation == HYPERVISOR.
	// For PROCESS isolation, this will be nil.
	host *uvm.UtilityVM

	phase sandboxPhase
}

// sandboxPhase represents the lifecycle phase of a sandbox.
type sandboxPhase int32

const (
	// sandboxUnknown is the zero-value; use it before the sandbox is handed to pod management.
	sandboxUnknown sandboxPhase = iota

	// sandboxPodManaged indicates the sandbox is known to/managed by the Pod
	// and is not managed via Sandbox APIs.
	sandboxPodManaged

	// sandboxCreated means CreateSandbox completed successfully.
	sandboxCreated

	// sandboxStarted means StartSandbox (or equivalent bootstrap) completed; workloads can run.
	sandboxStarted

	// sandboxTerminated means sandbox tear-down is complete; resources are released.
	sandboxTerminated
)

// String provides readable names for logs/metrics.
func (s sandboxPhase) String() string {
	switch s {
	case sandboxUnknown:
		return "sandboxUnknown"
	case sandboxPodManaged:
		return "sandboxPodManaged"
	case sandboxCreated:
		return "sandboxCreated"
	case sandboxStarted:
		return "sandboxStarted"
	case sandboxTerminated:
		return "sandboxTerminated"
	default:
		return "sandboxPhase(<invalid>)"
	}
}

const (
	// SandboxStateReady indicates the sandbox is ready.
	SandboxStateReady = "SANDBOX_READY"
	// SandboxStateNotReady indicates the sandbox is not ready.
	SandboxStateNotReady = "SANDBOX_NOTREADY"
)
