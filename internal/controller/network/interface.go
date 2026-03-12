//go:build windows

package network

import "context"

// Controller manages the network namespace and endpoints for a single pod.
// One Controller instance is owned by each pod.Controller.
type Controller interface {
	Setup(ctx context.Context, opts *SetupOptions) error

	Teardown(ctx context.Context) error

	// Status returns a snapshot of the current network state for the pod.
	Status() *Status
}

type SetupOptions struct {
	NetworkNamespace string
	EndpointIDs      []string
}

// Status captures the live network state of a pod.
type Status struct {
	NamespaceID string
	EndpointIDs []string
}
