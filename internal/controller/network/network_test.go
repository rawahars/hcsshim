//go:build windows && !wcow

package network_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Microsoft/hcsshim/hcn"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"

	"github.com/Microsoft/hcsshim/internal/controller/network"
	netmock "github.com/Microsoft/hcsshim/internal/controller/network/mock"
	gcsmock "github.com/Microsoft/hcsshim/internal/gcs/mock"

	"go.uber.org/mock/gomock"
)

var errTest = errors.New("test error")

// newTestManager creates a Manager wired with mock dependencies.
func newTestManager(t *testing.T, ctrl *gomock.Controller, namespaceSupportEnabled bool) (
	*network.Manager,
	*netmock.MockvmNetworkManager,
	*netmock.MocklinuxGuestNetworkManager,
) {
	t.Helper()

	mockVM := netmock.NewMockvmNetworkManager(ctrl)
	mockGuest := netmock.NewMocklinuxGuestNetworkManager(ctrl)
	mockCaps := netmock.NewMockcapabilitiesProvider(ctrl)

	if namespaceSupportEnabled {
		mockGuestCaps := gcsmock.NewMockGuestDefinedCapabilities(ctrl)
		mockGuestCaps.EXPECT().IsNamespaceAddRequestSupported().Return(true)
		mockCaps.EXPECT().Capabilities().Return(mockGuestCaps)
	} else {
		mockCaps.EXPECT().Capabilities().Return(nil)
	}

	m := network.New(mockVM, mockGuest, nil, mockCaps)
	return m, mockVM, mockGuest
}

// TestTeardown_PartialEndpointFailureContinues — if one NIC removal fails, remaining NICs still attempted.
func TestTeardown_PartialEndpointFailureContinues(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	m, mockVM, mockGuest := newTestManager(t, ctrl, true)

	// Simulate Configured state with 3 endpoints.
	m.SetStateForTest(network.StateConfigured)
	m.SetNamespaceIDForTest("test-ns")
	ep1 := &hcn.HostComputeEndpoint{Id: "ep-1", Name: "ep1", MacAddress: "aa:bb:cc:dd:ee:01"}
	ep2 := &hcn.HostComputeEndpoint{Id: "ep-2", Name: "ep2", MacAddress: "aa:bb:cc:dd:ee:02"}
	ep3 := &hcn.HostComputeEndpoint{Id: "ep-3", Name: "ep3", MacAddress: "aa:bb:cc:dd:ee:03"}
	m.AddEndpointForTest("nic-1", ep1)
	m.AddEndpointForTest("nic-2", ep2)
	m.AddEndpointForTest("nic-3", ep3)

	// Guest remove for nic-2 fails; others succeed.
	// We use AnyTimes because map iteration order is random.
	// DoAndReturn validates NamespaceID is correct for every call.
	mockGuest.EXPECT().RemoveLCOWNetworkInterface(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, settings *guestresource.LCOWNetworkAdapter) error {
			if settings.NamespaceID != "test-ns" {
				return fmt.Errorf("unexpected namespace: got %q, want %q", settings.NamespaceID, "test-ns")
			}
			if settings.ID == "nic-2" {
				return errTest
			}
			return nil
		}).AnyTimes()

	// Validate RemoveNIC receives the correct NetworkAdapter for each nicID.
	endpointsByNIC := map[string]*hcn.HostComputeEndpoint{"nic-1": ep1, "nic-2": ep2, "nic-3": ep3}
	mockVM.EXPECT().RemoveNIC(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, nicID string, adapter *hcsschema.NetworkAdapter) error {
			expected := endpointsByNIC[nicID]
			if adapter.EndpointId != expected.Id || adapter.MacAddress != expected.MacAddress {
				return fmt.Errorf("RemoveNIC(%s): adapter mismatch: got {%s, %s}, want {%s, %s}",
					nicID, adapter.EndpointId, adapter.MacAddress, expected.Id, expected.MacAddress)
			}
			return nil
		}).AnyTimes()

	err := m.Teardown(context.Background())
	if err == nil {
		t.Fatal("expected error from partial teardown, got nil")
	}

	// State must be Invalid (not TornDown) after partial failure.
	if m.StateForTest() != network.StateInvalid {
		t.Errorf("expected state Invalid, got %v", m.StateForTest())
	}

	// The failed NIC must still be in the map for retry.
	remaining := m.EndpointsForTest()
	if _, ok := remaining["nic-2"]; !ok {
		t.Error("expected nic-2 to remain in vmEndpoints for retry, but it was deleted")
	}
	// Successful NICs should have been removed.
	if len(remaining) > 1 {
		// Due to map iteration randomness we might have 1 or more failed.
		// But nic-2 must be present.
		for k := range remaining {
			if k != "nic-2" {
				t.Errorf("expected only nic-2 to remain, but found %s", k)
			}
		}
	}
}

// TestTeardown_RetryAfterPartialFailure — Teardown from Invalid retries remaining endpoints.
func TestTeardown_RetryAfterPartialFailure(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	m, mockVM, mockGuest := newTestManager(t, ctrl, true)

	// Start in Invalid state with 1 remaining endpoint (from a prior failed teardown).
	m.SetStateForTest(network.StateInvalid)
	m.SetNamespaceIDForTest("test-ns")
	ep := &hcn.HostComputeEndpoint{Id: "ep-remain", Name: "remaining", MacAddress: "aa:bb:cc:dd:ee:99"}
	m.AddEndpointForTest("nic-remain", ep)

	// This time removal succeeds. Verify concrete structs.
	gomock.InOrder(
		mockGuest.EXPECT().RemoveLCOWNetworkInterface(gomock.Any(), &guestresource.LCOWNetworkAdapter{
			NamespaceID: "test-ns",
			ID:          "nic-remain",
		}).Return(nil),
		mockVM.EXPECT().RemoveNIC(gomock.Any(), "nic-remain", &hcsschema.NetworkAdapter{
			EndpointId: "ep-remain",
			MacAddress: "aa:bb:cc:dd:ee:99",
		}).Return(nil),
	)

	err := m.Teardown(context.Background())
	if err != nil {
		t.Fatalf("expected successful retry teardown, got: %v", err)
	}

	if m.StateForTest() != network.StateTornDown {
		t.Errorf("expected state TornDown after successful retry, got %v", m.StateForTest())
	}
	if len(m.EndpointsForTest()) != 0 {
		t.Errorf("expected empty vmEndpoints after retry, got %d entries", len(m.EndpointsForTest()))
	}
}

// TestTeardown_IdempotentWhenTornDown — double-teardown returns nil.
func TestTeardown_IdempotentWhenTornDown(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	m, _, _ := newTestManager(t, ctrl, true)

	m.SetStateForTest(network.StateTornDown)

	err := m.Teardown(context.Background())
	if err != nil {
		t.Fatalf("expected nil for idempotent teardown, got: %v", err)
	}
	if m.StateForTest() != network.StateTornDown {
		t.Errorf("expected state TornDown, got %v", m.StateForTest())
	}
}

// TestTeardown_NoOpWhenNotConfigured — Teardown on unconfigured network returns nil.
func TestTeardown_NoOpWhenNotConfigured(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	m, _, _ := newTestManager(t, ctrl, true)

	// Default state is NotConfigured.
	err := m.Teardown(context.Background())
	if err != nil {
		t.Fatalf("expected nil for unconfigured teardown, got: %v", err)
	}
	if m.StateForTest() != network.StateNotConfigured {
		t.Errorf("expected state NotConfigured unchanged, got %v", m.StateForTest())
	}
}

// TestTeardown_FullLifecycle — Configured→TornDown with all endpoints removed.
func TestTeardown_FullLifecycle(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	m, mockVM, mockGuest := newTestManager(t, ctrl, true)

	m.SetStateForTest(network.StateConfigured)
	m.SetNamespaceIDForTest("test-ns")
	ep1 := &hcn.HostComputeEndpoint{Id: "ep-1", Name: "ep1", MacAddress: "aa:bb:cc:dd:ee:01"}
	ep2 := &hcn.HostComputeEndpoint{Id: "ep-2", Name: "ep2", MacAddress: "aa:bb:cc:dd:ee:02"}
	m.AddEndpointForTest("nic-1", ep1)
	m.AddEndpointForTest("nic-2", ep2)

	// Validate per-NIC struct correctness via DoAndReturn (map iteration is random).
	endpointsByNIC := map[string]*hcn.HostComputeEndpoint{"nic-1": ep1, "nic-2": ep2}
	mockGuest.EXPECT().RemoveLCOWNetworkInterface(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, settings *guestresource.LCOWNetworkAdapter) error {
			if settings.NamespaceID != "test-ns" {
				return fmt.Errorf("unexpected namespace: got %q, want %q", settings.NamespaceID, "test-ns")
			}
			return nil
		}).Times(2)
	mockVM.EXPECT().RemoveNIC(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, nicID string, adapter *hcsschema.NetworkAdapter) error {
			expected := endpointsByNIC[nicID]
			if adapter.EndpointId != expected.Id || adapter.MacAddress != expected.MacAddress {
				return fmt.Errorf("RemoveNIC(%s): adapter mismatch", nicID)
			}
			return nil
		}).Times(2)

	err := m.Teardown(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if m.StateForTest() != network.StateTornDown {
		t.Errorf("expected state TornDown, got %v", m.StateForTest())
	}
	if len(m.EndpointsForTest()) != 0 {
		t.Errorf("expected empty vmEndpoints, got %d entries", len(m.EndpointsForTest()))
	}
}

// TestSetup_DuplicateCallRejected — Setup on already-Configured manager returns error.
func TestSetup_DuplicateCallRejected(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	m, _, _ := newTestManager(t, ctrl, true)

	m.SetStateForTest(network.StateConfigured)

	err := m.Setup(context.Background(), &network.SetupOptions{NetworkNamespace: "ns-dup"})
	if err == nil {
		t.Fatal("expected error for duplicate Setup, got nil")
	}
	if !strings.Contains(err.Error(), "cannot set up network") {
		t.Errorf("expected error about state guard, got: %v", err)
	}
	if m.StateForTest() != network.StateConfigured {
		t.Errorf("expected state Configured unchanged, got %v", m.StateForTest())
	}
}

// TestNew_NilCapabilitiesDisablesGuestOps — nil Capabilities() skips guest-side NIC operations.
func TestNew_NilCapabilitiesDisablesGuestOps(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	m, mockVM, _ := newTestManager(t, ctrl, false /* nil caps */)

	if m.IsNamespaceSupportedForTest() {
		t.Fatal("expected isNamespaceSupportedByGuest=false when caps are nil")
	}

	// With namespace support disabled, addEndpoint should only call AddNIC (host-side).
	ep := &hcn.HostComputeEndpoint{Id: "ep-1", MacAddress: "aa:bb:cc:dd:ee:01"}
	mockVM.EXPECT().AddNIC(gomock.Any(), "nic-1", &hcsschema.NetworkAdapter{
		EndpointId: "ep-1",
		MacAddress: "aa:bb:cc:dd:ee:01",
	}).Return(nil)
	// Guest AddLCOWNetworkInterface must NOT be called (no EXPECT set = fail if called).

	err := m.AddEndpointToGuestNamespaceForTest(context.Background(), "nic-1", ep, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// NIC should still be tracked even without guest config.
	if _, ok := m.EndpointsForTest()["nic-1"]; !ok {
		t.Error("expected nic-1 to be tracked in vmEndpoints")
	}
}

// TestTeardown_WithoutNamespaceSupport — Teardown with no guest namespace support only calls host RemoveNIC.
func TestTeardown_WithoutNamespaceSupport(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	m, mockVM, _ := newTestManager(t, ctrl, false /* nil caps */)

	m.SetStateForTest(network.StateConfigured)
	m.SetNamespaceIDForTest("test-ns")
	ep := &hcn.HostComputeEndpoint{Id: "ep-1", Name: "ep1", MacAddress: "aa:bb:cc:dd:ee:01"}
	m.AddEndpointForTest("nic-1", ep)

	// Only host-side remove should be called (no guest remove expected).
	mockVM.EXPECT().RemoveNIC(gomock.Any(), "nic-1", &hcsschema.NetworkAdapter{
		EndpointId: "ep-1",
		MacAddress: "aa:bb:cc:dd:ee:01",
	}).Return(nil)

	err := m.Teardown(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.StateForTest() != network.StateTornDown {
		t.Errorf("expected state TornDown, got %v", m.StateForTest())
	}
}
