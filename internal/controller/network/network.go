//go:build windows

package network

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/Microsoft/hcsshim/hcn"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/logfields"
	"github.com/Microsoft/hcsshim/internal/vm/guestmanager"
	"github.com/Microsoft/hcsshim/internal/vm/vmmanager"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/sirupsen/logrus"
)

// Manager is the concrete implementation of [Controller].
type Manager struct {
	mu sync.Mutex

	// podID is the identifier of the pod whose network this Controller manages.
	podID string

	// namespaceID is the HCN namespace ID in use after a successful Setup.
	namespaceID string

	// vmEndpoints maps nicID (ID within UVM) -> HCN endpoint.
	vmEndpoints map[string]*hcn.HostComputeEndpoint

	// netState is the current lifecycle state of the network.
	netState State

	// isNamespaceSupportedByGuest determines if network namespace is supported inside the guest
	isNamespaceSupportedByGuest bool

	// vmNetManager performs host-side NIC hot-add/remove on the UVM.
	vmNetManager vmmanager.NetworkManager

	// linuxGuestMgr performs guest-side NIC inject/remove for LCOW.
	linuxGuestMgr guestmanager.LCOWNetworkManager

	// winGuestMgr performs guest-side NIC/namespace operations for WCOW.
	winGuestMgr guestmanager.WCOWNetworkManager

	// capsProvider exposes the guest's declared capabilities.
	// Used to check IsNamespaceAddRequestSupported.
	capsProvider capabilitiesProvider
}

// Assert that Manager implements Controller.
var _ Controller = (*Manager)(nil)

// New creates a ready-to-use Manager in [StateNotConfigured].
//
// This method is called from [VMController.CreateNetworkController()]
// which injects the necessary dependencies.
func New(
	vmNetManager vmmanager.NetworkManager,
	linuxGuestMgr guestmanager.LCOWNetworkManager,
	windowsGuestMgr guestmanager.WCOWNetworkManager,
	capsProvider capabilitiesProvider,
) *Manager {
	m := &Manager{
		vmNetManager:  vmNetManager,
		linuxGuestMgr: linuxGuestMgr,
		winGuestMgr:   windowsGuestMgr,
		capsProvider:  capsProvider,
		netState:      StateNotConfigured,
		vmEndpoints:   make(map[string]*hcn.HostComputeEndpoint),
	}

	// Cache once at construction so hot-add paths can branch without re-querying.
	if caps := capsProvider.Capabilities(); caps != nil {
		m.isNamespaceSupportedByGuest = caps.IsNamespaceAddRequestSupported()
	}

	return m
}

// Setup attaches the requested HCN namespace to the guest VM
// and hot-adds all endpoints found in that namespace.
// It must be called only once; subsequent calls return an error.
func (m *Manager) Setup(ctx context.Context, opts *SetupOptions) (err error) {
	ctx, _ = log.WithContext(ctx, logrus.WithField(logfields.Operation, "Network Setup"))

	m.mu.Lock()
	defer m.mu.Unlock()

	log.G(ctx).WithFields(logrus.Fields{
		logfields.PodID:     opts.PodID,
		logfields.Namespace: opts.NetworkNamespace,
	}).Debug("starting network setup")

	// If Setup has already been called, then error out.
	if m.netState != StateNotConfigured {
		return fmt.Errorf("cannot set up network in state %s", m.netState)
	}

	defer func() {
		if err != nil {
			// If setup fails for any reason, move to invalid so no further
			// Setup calls are accepted.
			m.netState = StateInvalid
			log.G(ctx).WithError(err).Error("network setup failed, moving to invalid state")
		}
	}()

	if opts.NetworkNamespace == "" {
		return fmt.Errorf("network namespace must not be empty")
	}

	// Validate that the provided namespace exists.
	hcnNamespace, err := hcn.GetNamespaceByID(opts.NetworkNamespace)
	if err != nil {
		return fmt.Errorf("get network namespace %s: %w", opts.NetworkNamespace, err)
	}

	// Fetch all endpoints in the namespace.
	endpoints, err := m.fetchEndpointsInNamespace(ctx, hcnNamespace)
	if err != nil {
		return fmt.Errorf("fetch endpoints in namespace %s: %w", hcnNamespace.Id, err)
	}

	// Add the namespace to the guest.
	if err = m.addNetNSInsideGuest(ctx, hcnNamespace); err != nil {
		return fmt.Errorf("add network namespace to guest: %w", err)
	}

	// Hot-add all endpoints in the namespace to the guest.
	for _, endpoint := range endpoints {
		nicGUID, err := guid.NewV4()
		if err != nil {
			return fmt.Errorf("generate NIC GUID: %w", err)
		}
		if err = m.addEndpointToGuestNamespace(ctx, nicGUID.String(), endpoint, opts.PolicyBasedRouting); err != nil {
			return fmt.Errorf("add endpoint %s to guest: %w", endpoint.Name, err)
		}
	}

	m.podID = opts.PodID
	m.namespaceID = hcnNamespace.Id
	m.netState = StateConfigured

	log.G(ctx).WithFields(logrus.Fields{
		logfields.PodID:     opts.PodID,
		logfields.Namespace: hcnNamespace.Id,
	}).Info("network setup completed successfully")

	return nil
}

// Teardown removes all guest-side NICs and the HCN namespace from the UVM.
//
// It is idempotent: calling it when the network is already torn down or not yet
// configured is a no-op.
func (m *Manager) Teardown(ctx context.Context) error {
	ctx, _ = log.WithContext(ctx, logrus.WithField(logfields.Operation, "Network Teardown"))

	m.mu.Lock()
	defer m.mu.Unlock()

	log.G(ctx).WithFields(logrus.Fields{
		logfields.PodID:     m.podID,
		logfields.Namespace: m.namespaceID,
		"State":             m.netState,
	}).Debug("starting network teardown")

	if m.netState == StateTornDown {
		// Teardown is idempotent, so return nil if already torn down.
		log.G(ctx).Info("network already torn down, skipping")
		return nil
	}

	if m.netState == StateNotConfigured {
		// Nothing was configured; nothing to clean up.
		log.G(ctx).Info("network not configured, skipping")
		return nil
	}

	// Remove all endpoints from the guest.
	// Use a continue-on-error strategy: attempt every NIC regardless of individual
	// failures, then collect all errors.
	var teardownErrs []error
	for nicID, endpoint := range m.vmEndpoints {
		if err := m.removeEndpointFromGuestNamespace(ctx, nicID, endpoint); err != nil {
			teardownErrs = append(teardownErrs, fmt.Errorf("remove endpoint %s from guest: %w", endpoint.Name, err))
			continue // continue attempting to remove other endpoints
		}

		delete(m.vmEndpoints, nicID)
	}

	if err := m.removeNetNSInsideGuest(ctx, m.namespaceID); err != nil {
		teardownErrs = append(teardownErrs, fmt.Errorf("remove network namespace from guest: %w", err))
	}

	if len(teardownErrs) > 0 {
		// If any errors were encountered during teardown, mark the state as invalid.
		m.netState = StateInvalid
		return errors.Join(teardownErrs...)
	}

	// Mark as torn down if we do not encounter any errors.
	// No further Setup or Teardown calls are allowed.
	m.netState = StateTornDown

	log.G(ctx).WithFields(logrus.Fields{
		logfields.PodID:    m.podID,
		"networkNamespace": m.namespaceID,
	}).Info("network teardown completed successfully")

	return nil
}

// fetchEndpointsInNamespace retrieves all HCN endpoints present in
// the given namespace.
// Endpoints are sorted so that those with names ending in "eth0" appear first.
func (m *Manager) fetchEndpointsInNamespace(ctx context.Context, ns *hcn.HostComputeNamespace) ([]*hcn.HostComputeEndpoint, error) {
	ctx, _ = log.WithContext(ctx, logrus.WithField(logfields.Namespace, ns.Id))
	log.G(ctx).Info("fetching endpoints from the network namespace")

	ids, err := hcn.GetNamespaceEndpointIds(ns.Id)
	if err != nil {
		return nil, fmt.Errorf("get endpoint IDs for namespace %s: %w", ns.Id, err)
	}
	endpoints := make([]*hcn.HostComputeEndpoint, 0, len(ids))
	for _, id := range ids {
		ep, err := hcn.GetEndpointByID(id)
		if err != nil {
			return nil, fmt.Errorf("get endpoint %s: %w", id, err)
		}
		endpoints = append(endpoints, ep)
	}

	// Ensure the endpoint named "eth0" is added first when multiple endpoints are present,
	// so it maps to eth0 inside the guest. CNI results aren't available here, so we rely
	// on the endpoint name suffix as a heuristic.
	cmp := func(a, b *hcn.HostComputeEndpoint) int {
		if strings.HasSuffix(a.Name, "eth0") {
			return -1
		}
		if strings.HasSuffix(b.Name, "eth0") {
			return 1
		}
		return 0
	}

	slices.SortStableFunc(endpoints, cmp)

	log.G(ctx).Tracef("fetched endpoints from the network namespace %+v", endpoints)

	return endpoints, nil
}
