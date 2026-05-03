//go:build windows && lcow

package vpci

import (
	"context"
	"testing"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"go.uber.org/mock/gomock"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/Microsoft/hcsshim/internal/controller/device/vpci/mocks"
	vpcisave "github.com/Microsoft/hcsshim/internal/controller/device/vpci/save"
)

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// roundTrip serializes src via Save, then rehydrates a new Controller via
// Import. The returned controller has not yet had Resume called.
func roundTrip(t *testing.T, src *Controller) *Controller {
	t.Helper()
	env, err := src.Save(context.Background())
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if env.GetTypeUrl() != vpcisave.TypeURL {
		t.Fatalf("unexpected TypeURL: got %q want %q", env.GetTypeUrl(), vpcisave.TypeURL)
	}
	dst, err := Import(env)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if !dst.isMigrating {
		t.Fatal("imported controller should be in isMigrating=true state")
	}
	return dst
}

// controllerCmpOpts deep-compares two [Controller] values for migration
// equivalence, ignoring runtime-only fields that legitimately differ between
// a live source and a freshly-imported (pre-Resume) destination.
var controllerCmpOpts = cmp.Options{
	cmp.AllowUnexported(
		Controller{},
		deviceInfo{},
	),
	cmpopts.IgnoreFields(Controller{}, "mu", "vmVPCI", "guestVPCI", "isMigrating"),
}

// assertControllerExactlyEqual fails the test if want and got differ in any
// persisted field (see [controllerCmpOpts] for what is excluded).
func assertControllerExactlyEqual(t *testing.T, want, got *Controller) {
	t.Helper()
	if diff := cmp.Diff(want, got, controllerCmpOpts); diff != "" {
		t.Errorf("controller state mismatch (-want +got):\n%s", diff)
	}
}

// resumeWith rebinds c to a fresh pair of host/guest mocks scoped to t,
// modeling a cross-shim handoff where the destination process owns its own
// vm/guest interface bindings.
func resumeWith(t *testing.T, c *Controller) (vm *mocks.MockvmVPCI, guest *mocks.MockguestVPCI) {
	t.Helper()
	ctrl := gomock.NewController(t)
	vm, guest = mocks.NewMockvmVPCI(ctrl), mocks.NewMockguestVPCI(ctrl)
	c.Resume(vm, guest)
	return vm, guest
}

// ─────────────────────────────────────────────────────────────────────────────
// Save / Import envelope tests
// ─────────────────────────────────────────────────────────────────────────────

// TestImport_NilEnvelope yields an empty controller in the migrating state.
func TestImport_NilEnvelope(t *testing.T) {
	t.Parallel()
	c, err := Import(nil)
	if err != nil {
		t.Fatalf("Import(nil): %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil controller")
	}
	if !c.isMigrating {
		t.Error("expected isMigrating=true")
	}
	if len(c.devices) != 0 || len(c.deviceToGUID) != 0 {
		t.Errorf("expected empty maps, got %d devices / %d device→GUID entries",
			len(c.devices), len(c.deviceToGUID))
	}
}

// TestImport_Errors covers the negative envelope-decoding paths: an unknown
// TypeURL, a payload that fails to unmarshal, and a payload whose schema
// version we do not recognize.
func TestImport_Errors(t *testing.T) {
	t.Parallel()
	badVersion, err := proto.Marshal(&vpcisave.Payload{SchemaVersion: vpcisave.SchemaVersion + 999})
	if err != nil {
		t.Fatalf("marshal bad version payload: %v", err)
	}
	tests := []struct {
		name string
		env  *anypb.Any
	}{
		{"WrongTypeURL", &anypb.Any{TypeUrl: "type.bogus/Foo"}},
		{"BadBytes", &anypb.Any{TypeUrl: vpcisave.TypeURL, Value: []byte{0xff, 0xff, 0xff}}},
		{"WrongSchemaVersion", &anypb.Any{TypeUrl: vpcisave.TypeURL, Value: badVersion}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Import(tt.env); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Round-trip equivalence tests
// ─────────────────────────────────────────────────────────────────────────────

// TestRoundTrip_PersistsState verifies that a wide variety of pre-add
// controller states (empty, single reservation, multiple reservations spanning
// distinct devices and VFs) survive a full Save→Import cycle byte-for-byte.
// The deviceToGUID reverse map rebuilt by Import is validated by
// assertControllerExactlyEqual.
func TestRoundTrip_PersistsState(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		devices []Device
	}{
		{name: "Empty"},
		{
			name: "SingleReservedDevice",
			devices: []Device{
				{DeviceInstanceID: "PCI\\VEN_1234&DEV_5678\\0", VirtualFunctionIndex: 0},
			},
		},
		{
			name: "MultipleHeterogeneousDevices",
			devices: []Device{
				{DeviceInstanceID: "PCI\\VEN_1111&DEV_AAAA\\0", VirtualFunctionIndex: 0},
				{DeviceInstanceID: "PCI\\VEN_2222&DEV_BBBB\\0", VirtualFunctionIndex: 0},
				{DeviceInstanceID: "PCI\\VEN_3333&DEV_CCCC\\0", VirtualFunctionIndex: 1},
				{DeviceInstanceID: "PCI\\VEN_3333&DEV_CCCC\\0", VirtualFunctionIndex: 2},
			},
		},
		{
			name: "DuplicateReservationsAreIdempotent",
			// The second/third Reserve for the same Device must return the
			// same GUID, leaving exactly two entries in the maps.
			devices: []Device{
				{DeviceInstanceID: "PCI\\VEN_AAAA&DEV_0001\\0", VirtualFunctionIndex: 0},
				{DeviceInstanceID: "PCI\\VEN_AAAA&DEV_0001\\0", VirtualFunctionIndex: 0},
				{DeviceInstanceID: "PCI\\VEN_AAAA&DEV_0001\\0", VirtualFunctionIndex: 0},
				{DeviceInstanceID: "PCI\\VEN_BBBB&DEV_0002\\0", VirtualFunctionIndex: 0},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			c := New(mocks.NewMockvmVPCI(ctrl), mocks.NewMockguestVPCI(ctrl))
			ctx := context.Background()
			for _, d := range tt.devices {
				if _, err := c.Reserve(ctx, d); err != nil {
					t.Fatalf("Reserve %s/%d: %v", d.DeviceInstanceID, d.VirtualFunctionIndex, err)
				}
			}

			dst := roundTrip(t, c)
			assertControllerExactlyEqual(t, c, dst)
		})
	}
}

// TestRoundTrip_AssignedDevice covers a Reserved → AddToVM (host + guest
// success) → save → import → resume sequence, and verifies that a post-resume
// AddToVM is idempotent (no host/guest calls re-issued, refCount bumped
// in-place).
func TestRoundTrip_AssignedDevice(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	vm := mocks.NewMockvmVPCI(ctrl)
	guest := mocks.NewMockguestVPCI(ctrl)
	c := New(vm, guest)
	ctx := context.Background()

	dev := Device{DeviceInstanceID: "PCI\\VEN_1234&DEV_5678\\0", VirtualFunctionIndex: 0}
	g, err := c.Reserve(ctx, dev)
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	vm.EXPECT().AddDevice(gomock.Any(), g, gomock.Any()).Return(nil)
	guest.EXPECT().AddVPCIDevice(gomock.Any(), gomock.Any()).Return(nil)
	if err := c.AddToVM(ctx, g); err != nil {
		t.Fatalf("AddToVM: %v", err)
	}

	dst := roundTrip(t, c)
	assertControllerExactlyEqual(t, c, dst)

	if got := dst.devices[g].state; got != StateReady {
		t.Errorf("device state after round-trip: want Ready got %s", got)
	}

	resumeWith(t, dst)
	// Idempotent AddToVM: no host/guest calls expected; refCount must bump.
	if err := dst.AddToVM(ctx, g); err != nil {
		t.Fatalf("post-resume AddToVM: %v", err)
	}
	if got := dst.devices[g].refCount; got != 2 {
		t.Errorf("refCount after post-resume AddToVM: want 2 got %d", got)
	}
}

// TestRoundTrip_RefCountedDevice covers two AddToVMs on the same device that
// are both ready. After round-trip + Resume, the first RemoveFromVM must NOT
// issue any host call (refCount drops 2→1) and the second must issue the host
// RemoveDevice.
func TestRoundTrip_RefCountedDevice(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	vm := mocks.NewMockvmVPCI(ctrl)
	guest := mocks.NewMockguestVPCI(ctrl)
	c := New(vm, guest)
	ctx := context.Background()

	dev := Device{DeviceInstanceID: "PCI\\VEN_REF&DEV_0001\\0", VirtualFunctionIndex: 0}
	g, _ := c.Reserve(ctx, dev)

	vm.EXPECT().AddDevice(gomock.Any(), g, gomock.Any()).Return(nil).Times(1)
	guest.EXPECT().AddVPCIDevice(gomock.Any(), gomock.Any()).Return(nil).Times(1)
	if err := c.AddToVM(ctx, g); err != nil {
		t.Fatalf("AddToVM #1: %v", err)
	}
	if err := c.AddToVM(ctx, g); err != nil {
		t.Fatalf("AddToVM #2: %v", err)
	}
	if got := c.devices[g].refCount; got != 2 {
		t.Fatalf("precondition: refCount=%d", got)
	}

	dst := roundTrip(t, c)
	assertControllerExactlyEqual(t, c, dst)

	dstVM, _ := resumeWith(t, dst)

	// First post-resume remove: no host call expected.
	if err := dst.RemoveFromVM(ctx, g); err != nil {
		t.Fatalf("first RemoveFromVM: %v", err)
	}
	if len(dst.devices) != 1 {
		t.Errorf("device should still exist; got %d devices", len(dst.devices))
	}
	if got := dst.devices[g].refCount; got != 1 {
		t.Errorf("refCount after first remove: want 1 got %d", got)
	}

	// Second post-resume remove: last ref → host RemoveDevice.
	dstVM.EXPECT().RemoveDevice(gomock.Any(), g).Return(nil).Times(1)
	if err := dst.RemoveFromVM(ctx, g); err != nil {
		t.Fatalf("second RemoveFromVM: %v", err)
	}
	if len(dst.devices) != 0 || len(dst.deviceToGUID) != 0 {
		t.Errorf("expected empty maps after final remove, got %d devices / %d device→GUID entries",
			len(dst.devices), len(dst.deviceToGUID))
	}
}

// TestRoundTrip_RemovedStateDrains covers a device whose host-side AddDevice
// failed, leaving it in StateRemoved (still tracked for caller-driven cleanup).
// After migration + Resume, RemoveFromVM must NOT issue any host call (the
// device was never added to the VM) and must clean up the maps.
func TestRoundTrip_RemovedStateDrains(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	vm := mocks.NewMockvmVPCI(ctrl)
	guest := mocks.NewMockguestVPCI(ctrl)
	c := New(vm, guest)
	ctx := context.Background()

	dev := Device{DeviceInstanceID: "PCI\\VEN_BAD&DEV_HOST\\0", VirtualFunctionIndex: 0}
	g, _ := c.Reserve(ctx, dev)

	vm.EXPECT().AddDevice(gomock.Any(), g, gomock.Any()).Return(errHostAdd)
	if err := c.AddToVM(ctx, g); err == nil {
		t.Fatal("expected AddToVM to fail")
	}

	// Sanity: the device is in StateRemoved before round-trip.
	if got := c.devices[g].state; got != StateRemoved {
		t.Fatalf("precondition: device state want Removed got %s", got)
	}

	dst := roundTrip(t, c)
	assertControllerExactlyEqual(t, c, dst)

	if got := dst.devices[g].state; got != StateRemoved {
		t.Errorf("device state after round-trip: want Removed got %s", got)
	}

	resumeWith(t, dst)

	// The fresh mocks have no expectations recorded, so any host call would
	// fail the test.
	if err := dst.RemoveFromVM(ctx, g); err != nil {
		t.Fatalf("RemoveFromVM: %v", err)
	}
	if len(dst.devices) != 0 || len(dst.deviceToGUID) != 0 {
		t.Errorf("expected clean state, got %d devices / %d device→GUID entries",
			len(dst.devices), len(dst.deviceToGUID))
	}
}

// TestRoundTrip_AssignedInvalidDrains is the guest-side counterpart to
// [TestRoundTrip_RemovedStateDrains]: the device's host-side add succeeded but
// the guest-side notification failed, leaving it in StateAssignedInvalid.
// After migration + Resume, RemoveFromVM MUST issue the host RemoveDevice (the
// host-side assignment exists) but no guest-side call (the guest never came
// up).
func TestRoundTrip_AssignedInvalidDrains(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	vm := mocks.NewMockvmVPCI(ctrl)
	guest := mocks.NewMockguestVPCI(ctrl)
	c := New(vm, guest)
	ctx := context.Background()

	dev := Device{DeviceInstanceID: "PCI\\VEN_BAD&DEV_GUEST\\0", VirtualFunctionIndex: 0}
	g, _ := c.Reserve(ctx, dev)

	vm.EXPECT().AddDevice(gomock.Any(), g, gomock.Any()).Return(nil)
	guest.EXPECT().AddVPCIDevice(gomock.Any(), gomock.Any()).Return(errGuestAdd)
	if err := c.AddToVM(ctx, g); err == nil {
		t.Fatal("expected AddToVM to fail at guest notification")
	}

	// Sanity: the device is in StateAssignedInvalid before round-trip.
	if got := c.devices[g].state; got != StateAssignedInvalid {
		t.Fatalf("precondition: device state want AssignedInvalid got %s", got)
	}

	dst := roundTrip(t, c)
	assertControllerExactlyEqual(t, c, dst)

	if got := dst.devices[g].state; got != StateAssignedInvalid {
		t.Errorf("device state after round-trip: want AssignedInvalid got %s", got)
	}

	dstVM, _ := resumeWith(t, dst)

	// Host-side RemoveDevice IS expected; guest call is NOT.
	dstVM.EXPECT().RemoveDevice(gomock.Any(), g).Return(nil).Times(1)
	if err := dst.RemoveFromVM(ctx, g); err != nil {
		t.Fatalf("RemoveFromVM: %v", err)
	}
	if len(dst.devices) != 0 || len(dst.deviceToGUID) != 0 {
		t.Errorf("expected clean state, got %d devices / %d device→GUID entries",
			len(dst.devices), len(dst.deviceToGUID))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Migration-state guard tests
// ─────────────────────────────────────────────────────────────────────────────

// TestMigrating_GuardThenResume verifies that the imported controller rejects
// public Reserve/AddToVM/RemoveFromVM until Resume binds the live host/guest
// interfaces, and that operations succeed once it does.
func TestMigrating_GuardThenResume(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	c := New(mocks.NewMockvmVPCI(ctrl), mocks.NewMockguestVPCI(ctrl))
	ctx := context.Background()

	dev := Device{DeviceInstanceID: "PCI\\VEN_GUARD&DEV_0001\\0", VirtualFunctionIndex: 0}
	g, _ := c.Reserve(ctx, dev)

	dst := roundTrip(t, c)

	if _, err := dst.Reserve(ctx, Device{DeviceInstanceID: "PCI\\VEN_NEW\\0", VirtualFunctionIndex: 0}); err == nil {
		t.Error("Reserve should fail while migrating")
	}
	if err := dst.AddToVM(ctx, g); err == nil {
		t.Error("AddToVM should fail while migrating")
	}
	if err := dst.RemoveFromVM(ctx, g); err == nil {
		t.Error("RemoveFromVM should fail while migrating")
	}

	resumeWith(t, dst)
	if dst.isMigrating {
		t.Error("isMigrating should be false after Resume")
	}
	if dst.vmVPCI == nil || dst.guestVPCI == nil {
		t.Error("Resume must bind vm/guest interfaces")
	}
	if _, err := dst.Reserve(ctx, Device{DeviceInstanceID: "PCI\\VEN_POST\\0", VirtualFunctionIndex: 0}); err != nil {
		t.Errorf("post-resume Reserve: %v", err)
	}
}

// TestEndToEnd_SaveImportResumeContinuesLifecycle exercises a full cross-shim
// workflow: build a controller with two devices (one fully assigned, one only
// reserved), serialize it, rehydrate on a fresh controller with new mocks,
// resume, and complete the lifecycle on the destination side.
func TestEndToEnd_SaveImportResumeContinuesLifecycle(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	vm := mocks.NewMockvmVPCI(ctrl)
	guest := mocks.NewMockguestVPCI(ctrl)
	c := New(vm, guest)
	ctx := context.Background()

	// Device #1: fully assigned.
	dev1 := Device{DeviceInstanceID: "PCI\\VEN_E2E&DEV_ASSIGNED\\0", VirtualFunctionIndex: 0}
	g1, _ := c.Reserve(ctx, dev1)
	vm.EXPECT().AddDevice(gomock.Any(), g1, gomock.Any()).Return(nil)
	guest.EXPECT().AddVPCIDevice(gomock.Any(), gomock.Any()).Return(nil)
	if err := c.AddToVM(ctx, g1); err != nil {
		t.Fatalf("AddToVM dev1: %v", err)
	}

	// Device #2: only reserved.
	dev2 := Device{DeviceInstanceID: "PCI\\VEN_E2E&DEV_RESERVED\\0", VirtualFunctionIndex: 1}
	g2, _ := c.Reserve(ctx, dev2)

	// Round-trip onto a fresh controller and bind new mocks (modeling the
	// destination shim owning its own vm/guest interface bindings).
	dst := roundTrip(t, c)
	assertControllerExactlyEqual(t, c, dst)
	dstVM, dstGuest := resumeWith(t, dst)

	// dev1: idempotent AddToVM (already StateReady) bumps refCount without
	// re-issuing any host/guest call.
	if err := dst.AddToVM(ctx, g1); err != nil {
		t.Fatalf("post-resume AddToVM dev1: %v", err)
	}
	if got := dst.devices[g1].refCount; got != 2 {
		t.Errorf("dev1 refCount post-resume: want 2 got %d", got)
	}

	// dev2: complete the lifecycle by assigning it now on the destination.
	dstVM.EXPECT().AddDevice(gomock.Any(), g2, gomock.Any()).Return(nil)
	dstGuest.EXPECT().AddVPCIDevice(gomock.Any(), gomock.Any()).Return(nil)
	if err := dst.AddToVM(ctx, g2); err != nil {
		t.Fatalf("post-resume AddToVM dev2: %v", err)
	}

	// Tear both down. dev1 needs two RemoveFromVM calls (refCount=2); only
	// the second triggers a host RemoveDevice. dev2 needs one.
	dstVM.EXPECT().RemoveDevice(gomock.Any(), g1).Return(nil).Times(1)
	dstVM.EXPECT().RemoveDevice(gomock.Any(), g2).Return(nil).Times(1)
	if err := dst.RemoveFromVM(ctx, g1); err != nil {
		t.Fatalf("post-resume RemoveFromVM dev1 (refCount→1): %v", err)
	}
	if err := dst.RemoveFromVM(ctx, g1); err != nil {
		t.Fatalf("post-resume RemoveFromVM dev1 (refCount→0): %v", err)
	}
	if err := dst.RemoveFromVM(ctx, g2); err != nil {
		t.Fatalf("post-resume RemoveFromVM dev2: %v", err)
	}
	if len(dst.devices) != 0 || len(dst.deviceToGUID) != 0 {
		t.Errorf("expected empty controller, got %d devices / %d device→GUID entries",
			len(dst.devices), len(dst.deviceToGUID))
	}

	// Sanity: the source GUIDs survived the round-trip identically.
	_ = guid.GUID{}
}
