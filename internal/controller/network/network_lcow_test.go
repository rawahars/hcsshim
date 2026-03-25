//go:build windows && !wcow

package network_test

import (
	"context"
	"testing"

	"github.com/Microsoft/hcsshim/hcn"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"

	"go.uber.org/mock/gomock"
)

// --- LCOW Endpoint Operation Tests ---

// TestAddEndpoint_SuccessWithNamespaceSupport — host AddNIC + guest AddLCOWNetworkInterface called in order, NIC tracked.
func TestAddEndpoint_SuccessWithNamespaceSupport(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	m, mockVM, mockGuest := newTestManager(t, ctrl, true)

	ep := &hcn.HostComputeEndpoint{
		Id:                   "ep-1",
		MacAddress:           "aa:bb:cc:dd:ee:01",
		HostComputeNamespace: "test-ns",
	}

	// Build the expected adapter using the same function the production code calls.
	expectedAdapter, err := guestresource.BuildLCOWNetworkAdapter("nic-1", ep, false)
	if err != nil {
		t.Fatalf("failed to build expected adapter: %v", err)
	}

	// Enforce ordering: host AddNIC first, then guest AddLCOWNetworkInterface.
	gomock.InOrder(
		mockVM.EXPECT().AddNIC(gomock.Any(), "nic-1", &hcsschema.NetworkAdapter{
			EndpointId: "ep-1",
			MacAddress: "aa:bb:cc:dd:ee:01",
		}).Return(nil),
		// Guest AddLCOWNetworkInterface must receive the adapter built by BuildLCOWNetworkAdapter.
		mockGuest.EXPECT().AddLCOWNetworkInterface(gomock.Any(), expectedAdapter).Return(nil),
	)

	if err = m.AddEndpointToGuestNamespaceForTest(context.Background(), "nic-1", ep, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := m.EndpointsForTest()["nic-1"]; !ok {
		t.Error("expected nic-1 to be tracked in vmEndpoints")
	}
}

// TestAddEndpoint_HostSucceedsGuestFails_StillTracked — NIC tracked in vmEndpoints even when guest add fails.
func TestAddEndpoint_HostSucceedsGuestFails_StillTracked(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	m, mockVM, mockGuest := newTestManager(t, ctrl, true)

	ep := &hcn.HostComputeEndpoint{
		Id:                   "ep-1",
		MacAddress:           "aa:bb:cc:dd:ee:01",
		HostComputeNamespace: "test-ns",
	}

	// Build the expected adapter to verify correct struct is passed even on failure path.
	expectedAdapter, buildErr := guestresource.BuildLCOWNetworkAdapter("nic-1", ep, false)
	if buildErr != nil {
		t.Fatalf("failed to build expected adapter: %v", buildErr)
	}

	gomock.InOrder(
		mockVM.EXPECT().AddNIC(gomock.Any(), "nic-1", &hcsschema.NetworkAdapter{
			EndpointId: "ep-1",
			MacAddress: "aa:bb:cc:dd:ee:01",
		}).Return(nil),
		mockGuest.EXPECT().AddLCOWNetworkInterface(gomock.Any(), expectedAdapter).Return(errTest),
	)

	err := m.AddEndpointToGuestNamespaceForTest(context.Background(), "nic-1", ep, false)
	if err == nil {
		t.Fatal("expected error when guest AddLCOWNetworkInterface fails, got nil")
	}

	// Critical: NIC must still be tracked for Teardown cleanup.
	if _, ok := m.EndpointsForTest()["nic-1"]; !ok {
		t.Error("expected nic-1 to remain tracked after guest failure (for Teardown cleanup)")
	}
}

// TestAddEndpoint_HostAddNICFails_NotTracked — NIC not added to vmEndpoints when AddNIC fails.
func TestAddEndpoint_HostAddNICFails_NotTracked(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	m, mockVM, _ := newTestManager(t, ctrl, true)

	ep := &hcn.HostComputeEndpoint{
		Id:         "ep-1",
		MacAddress: "aa:bb:cc:dd:ee:01",
	}

	mockVM.EXPECT().AddNIC(gomock.Any(), "nic-1", &hcsschema.NetworkAdapter{
		EndpointId: "ep-1",
		MacAddress: "aa:bb:cc:dd:ee:01",
	}).Return(errTest)

	err := m.AddEndpointToGuestNamespaceForTest(context.Background(), "nic-1", ep, false)
	if err == nil {
		t.Fatal("expected error when AddNIC fails, got nil")
	}

	// NIC must NOT be tracked — AddNIC failed before the tracking line.
	if _, ok := m.EndpointsForTest()["nic-1"]; ok {
		t.Error("expected nic-1 NOT to be tracked after AddNIC failure")
	}
}

// TestRemoveEndpoint_Success — guest remove called before host remove.
func TestRemoveEndpoint_Success(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	m, mockVM, mockGuest := newTestManager(t, ctrl, true)

	m.SetNamespaceIDForTest("test-ns")
	ep := &hcn.HostComputeEndpoint{
		Id:         "ep-1",
		MacAddress: "aa:bb:cc:dd:ee:01",
	}

	// Enforce ordering: guest first, then host.
	gomock.InOrder(
		mockGuest.EXPECT().RemoveLCOWNetworkInterface(gomock.Any(), &guestresource.LCOWNetworkAdapter{
			NamespaceID: "test-ns",
			ID:          "nic-1",
		}).Return(nil),
		mockVM.EXPECT().RemoveNIC(gomock.Any(), "nic-1", &hcsschema.NetworkAdapter{
			EndpointId: "ep-1",
			MacAddress: "aa:bb:cc:dd:ee:01",
		}).Return(nil),
	)

	err := m.RemoveEndpointFromGuestNamespaceForTest(context.Background(), "nic-1", ep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestRemoveEndpoint_GuestRemoveFails_HostNotCalled — host RemoveNIC not called when guest remove fails.
func TestRemoveEndpoint_GuestRemoveFails_HostNotCalled(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	m, _, mockGuest := newTestManager(t, ctrl, true)

	m.SetNamespaceIDForTest("test-ns")
	ep := &hcn.HostComputeEndpoint{
		Id:         "ep-1",
		MacAddress: "aa:bb:cc:dd:ee:01",
	}

	mockGuest.EXPECT().RemoveLCOWNetworkInterface(gomock.Any(), &guestresource.LCOWNetworkAdapter{
		NamespaceID: "test-ns",
		ID:          "nic-1",
	}).Return(errTest)
	// No RemoveNIC EXPECT — gomock will fail if it's called.

	err := m.RemoveEndpointFromGuestNamespaceForTest(context.Background(), "nic-1", ep)
	if err == nil {
		t.Fatal("expected error when guest remove fails, got nil")
	}
}

// TestRemoveEndpoint_WithoutNamespaceSupport — only host RemoveNIC called when guest namespace not supported.
func TestRemoveEndpoint_WithoutNamespaceSupport(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	m, mockVM, _ := newTestManager(t, ctrl, false /* no namespace support */)

	m.SetNamespaceIDForTest("test-ns")
	ep := &hcn.HostComputeEndpoint{
		Id:         "ep-1",
		MacAddress: "aa:bb:cc:dd:ee:01",
	}

	// Only host remove should be called.
	mockVM.EXPECT().RemoveNIC(gomock.Any(), "nic-1", &hcsschema.NetworkAdapter{
		EndpointId: "ep-1",
		MacAddress: "aa:bb:cc:dd:ee:01",
	}).Return(nil)

	err := m.RemoveEndpointFromGuestNamespaceForTest(context.Background(), "nic-1", ep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
