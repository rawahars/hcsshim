//go:build windows && (lcow || wcow)

package network

import (
	"context"
	"errors"
	"fmt"

	"github.com/Microsoft/hcsshim/hcn"
	netsave "github.com/Microsoft/hcsshim/internal/controller/network/save"
	"github.com/Microsoft/hcsshim/internal/log"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// Save returns the network controller's migration payload as an [anypb.Any]
// tagged with [netsave.TypeURL]. The returned envelope captures the
// namespace identifier, routing/capability flags, and the per-NIC HCN
// endpoint bindings the destination needs to re-attach the pod's network
// on resume.
func (c *Controller) Save(_ context.Context) (*anypb.Any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	state := &netsave.Payload{
		NamespaceID:                 c.namespaceID,
		PolicyBasedRouting:          c.policyBasedRouting,
		State:                       netsave.Stage(c.netState),
		IsNamespaceSupportedByGuest: c.isNamespaceSupportedByGuest,
		VmEndpoints:                 make(map[string]*netsave.EndpointBinding, len(c.vmEndpoints)),
	}
	for nicID, ep := range c.vmEndpoints {
		if ep == nil {
			continue
		}
		state.VmEndpoints[nicID] = &netsave.EndpointBinding{
			EndpointID:   ep.Id,
			MacAddress:   ep.MacAddress,
			EndpointName: ep.Name,
		}
	}

	payload, err := proto.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("marshal network saved state: %w", err)
	}
	return &anypb.Any{TypeUrl: netsave.TypeURL, Value: payload}, nil
}

// Import rehydrates a [Controller] from a [Controller.Save]'d envelope
// without binding any host/guest interfaces. The returned controller is
// placed in [StateMigrating] so all operational APIs reject calls until
// [Controller.Resume] supplies the live interfaces and the next state.
func Import(env *anypb.Any) (*Controller, error) {
	state := &netsave.Payload{}
	if env != nil {
		if env.GetTypeUrl() != netsave.TypeURL {
			return nil, fmt.Errorf("unsupported network saved-state type %q", env.GetTypeUrl())
		}
		if err := proto.Unmarshal(env.GetValue(), state); err != nil {
			return nil, fmt.Errorf("unmarshal network saved state: %w", err)
		}
		if v := state.GetSchemaVersion(); v != netsave.SchemaVersion {
			return nil, fmt.Errorf("unsupported network saved-state schema version %d (want %d)", v, netsave.SchemaVersion)
		}
	}

	c := &Controller{
		vmEndpoints: make(map[string]*hcn.HostComputeEndpoint),
		netState:    StateMigrating,
	}

	c.namespaceID = state.GetNamespaceID()
	c.policyBasedRouting = state.GetPolicyBasedRouting()
	c.isNamespaceSupportedByGuest = state.GetIsNamespaceSupportedByGuest()

	for nicID, b := range state.GetVmEndpoints() {
		if nicID == "" || b == nil {
			continue
		}
		c.vmEndpoints[nicID] = &hcn.HostComputeEndpoint{
			Id:         b.GetEndpointID(),
			MacAddress: b.GetMacAddress(),
			Name:       b.GetEndpointName(),
		}
	}
	return c, nil
}

// Resume binds the live host/guest interfaces to a controller previously
// produced by [Import] and transitions it from [StateMigrating] into the
// caller-supplied next state. Must be called once the destination VM is
// running before any setup, teardown, or NIC operation is invoked.
func (c *Controller) Resume(
	next State,
	vmNetManager vmNetworkManager,
	guestNetwork guestNetwork,
	capsProvider capabilitiesProvider,
) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.vmNetwork = vmNetManager
	c.guestNetwork = guestNetwork
	c.capsProvider = capsProvider
	c.netState = next
}

// todo: fix this properly for post-migration
func (c *Controller) ResetForMigration(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.vmEndpoints) == 0 {
		c.netState = StateNotConfigured
		return nil
	}

	var errs []error
	for nicID, ep := range c.vmEndpoints {
		if err := c.removeEndpointFromGuestNamespace(ctx, nicID, ep); err != nil {
			errs = append(errs, fmt.Errorf("reset stale source NIC %s (endpoint %s): %w", nicID, ep.Id, err))
			continue
		}
		delete(c.vmEndpoints, nicID)
	}

	if len(errs) > 0 {
		// Leave c.netState untouched so the caller can retry.
		return errors.Join(errs...)
	}

	c.netState = StateNotConfigured
	log.G(ctx).Info("network reset for migration: source NIC bindings cleared, namespace preserved")
	return nil
}
