//go:build windows

package network

import (
	"context"

	"github.com/Microsoft/hcsshim/hcn"
)

// SetStateForTest sets the Manager's state. Test-only.
func (m *Manager) SetStateForTest(s State) {
	m.netState = s
}

// StateForTest returns the Manager's current state. Test-only.
func (m *Manager) StateForTest() State {
	return m.netState
}

// SetNamespaceIDForTest sets the namespace ID on the Manager. Test-only.
func (m *Manager) SetNamespaceIDForTest(id string) {
	m.namespaceID = id
}

// AddEndpointForTest adds a NIC→endpoint mapping to the internal tracking map. Test-only.
func (m *Manager) AddEndpointForTest(nicID string, ep *hcn.HostComputeEndpoint) {
	m.vmEndpoints[nicID] = ep
}

// EndpointsForTest returns the current vmEndpoints map. Test-only.
func (m *Manager) EndpointsForTest() map[string]*hcn.HostComputeEndpoint {
	return m.vmEndpoints
}

// IsNamespaceSupportedForTest returns the cached namespace-support flag. Test-only.
func (m *Manager) IsNamespaceSupportedForTest() bool {
	return m.isNamespaceSupportedByGuest
}

// AddEndpointToGuestNamespaceForTest exposes addEndpointToGuestNamespace for testing.
func (m *Manager) AddEndpointToGuestNamespaceForTest(ctx context.Context, nicID string, endpoint *hcn.HostComputeEndpoint, policyBasedRouting bool) error {
	return m.addEndpointToGuestNamespace(ctx, nicID, endpoint, policyBasedRouting)
}

// RemoveEndpointFromGuestNamespaceForTest exposes removeEndpointFromGuestNamespace for testing.
func (m *Manager) RemoveEndpointFromGuestNamespaceForTest(ctx context.Context, nicID string, endpoint *hcn.HostComputeEndpoint) error {
	return m.removeEndpointFromGuestNamespace(ctx, nicID, endpoint)
}
