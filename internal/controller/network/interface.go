//go:build windows

package network

import (
	"context"

	"github.com/Microsoft/hcsshim/internal/gcs"
)

// Controller manages the network lifecycle for a single pod running inside a UVM.
type Controller interface {
	// Setup attaches the HCN namespace and its endpoints to the guest VM.
	Setup(ctx context.Context, opts *SetupOptions) error

	// Teardown removes all guest-side NICs and the network namespace from the VM.
	// It is idempotent: calling it on an already torn-down or unconfigured network is a no-op.
	Teardown(ctx context.Context) error
}

// SetupOptions holds the configuration required to set up the network for a pod.
type SetupOptions struct {
	// PodID is the identifier of the pod whose network is being configured.
	PodID string

	// NetworkNamespace is the HCN namespace ID to attach to the guest.
	NetworkNamespace string

	// PolicyBasedRouting controls whether policy-based routing is configured
	// for the endpoints added to the guest. Only relevant for LCOW.
	PolicyBasedRouting bool
}

// capabilitiesProvider is a narrow interface satisfied by guestmanager.Manager.
// It exists so callers pass the guest manager scoped only to Capabilities(),
// avoiding a hard dependency on the full guestmanager.Manager interface here.
type capabilitiesProvider interface {
	Capabilities() gcs.GuestDefinedCapabilities
}
