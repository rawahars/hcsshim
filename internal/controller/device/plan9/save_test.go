//go:build windows && lcow

package plan9

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"go.uber.org/mock/gomock"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/Microsoft/hcsshim/internal/controller/device/plan9/mount"
	plan9save "github.com/Microsoft/hcsshim/internal/controller/device/plan9/save"
	"github.com/Microsoft/hcsshim/internal/controller/device/plan9/share"
)

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// roundTrip serializes src via Save, then rehydrates a new Controller via
// Import. The returned controller has not yet had Resume called.
func roundTrip(t *testing.T, src *Controller) *Controller {
	t.Helper()
	env, err := src.Save(nil)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if env.GetTypeUrl() != plan9save.TypeURL {
		t.Fatalf("unexpected TypeURL: got %q want %q", env.GetTypeUrl(), plan9save.TypeURL)
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
		reservation{},
		share.Share{},
		share.Config{},
		mount.Mount{},
		mount.Config{},
	),
	cmpopts.IgnoreFields(Controller{}, "mu", "vmPlan9", "guest", "isMigrating"),
}

// assertControllerExactlyEqual fails the test if want and got differ in any
// persisted field (see [controllerCmpOpts] for what is excluded).
func assertControllerExactlyEqual(t *testing.T, want, got *Controller) {
	t.Helper()
	if diff := cmp.Diff(want, got, controllerCmpOpts); diff != "" {
		t.Errorf("controller state mismatch (-want +got):\n%s", diff)
	}
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
	if len(c.reservations) != 0 || len(c.sharesByHostPath) != 0 {
		t.Errorf("expected empty maps, got %d reservations / %d shares", len(c.reservations), len(c.sharesByHostPath))
	}
	if c.nameCounter != 0 {
		t.Errorf("expected nameCounter=0, got %d", c.nameCounter)
	}
}

// TestImport_Errors covers the negative envelope-decoding paths: an unknown
// TypeURL, a payload that fails to unmarshal, and a payload whose schema
// version we do not recognize.
func TestImport_Errors(t *testing.T) {
	t.Parallel()
	badVersion, err := proto.Marshal(&plan9save.Payload{SchemaVersion: plan9save.SchemaVersion + 999})
	if err != nil {
		t.Fatalf("marshal bad version payload: %v", err)
	}
	tests := []struct {
		name string
		env  *anypb.Any
	}{
		{"WrongTypeURL", &anypb.Any{TypeUrl: "type.bogus/Foo"}},
		{"BadBytes", &anypb.Any{TypeUrl: plan9save.TypeURL, Value: []byte{0xff, 0xff, 0xff}}},
		{"WrongSchemaVersion", &anypb.Any{TypeUrl: plan9save.TypeURL, Value: badVersion}},
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

// TestRoundTrip_PersistsState verifies that a wide variety of pre-mount
// controller states (empty, policy flags, single/multiple shares with
// heterogeneous configs, multiple reservations per share) survive a full
// Save→Import cycle byte-for-byte. The reservation→share-name link rebuilt
// by Import is validated by assertControllerExactlyEqual.
func TestRoundTrip_PersistsState(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                 string
		noWritableFileShares bool
		configs              []share.Config
	}{
		{name: "Empty"},
		{name: "NoWritablePolicy", noWritableFileShares: true},
		{
			name: "SingleReservedShare",
			configs: []share.Config{
				{HostPath: "/host/a", ReadOnly: true, Restrict: true, AllowedNames: []string{"foo", "bar"}},
			},
		},
		{
			name: "MultipleHeterogeneousShares",
			configs: []share.Config{
				{HostPath: "/h/0"},
				{HostPath: "/h/1", ReadOnly: true},
				{HostPath: "/h/2", Restrict: true, AllowedNames: []string{"a", "b", "c"}},
				{HostPath: "/h/3", ReadOnly: true, Restrict: true, AllowedNames: []string{"only"}},
			},
		},
		{
			name: "MultipleReservationsPerShare",
			configs: []share.Config{
				{HostPath: "/h/x"}, {HostPath: "/h/x"},
				{HostPath: "/h/y"}, {HostPath: "/h/y"},
				{HostPath: "/h/z"}, {HostPath: "/h/z"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tc := newTestController(t, tt.noWritableFileShares)
			for _, cfg := range tt.configs {
				if _, err := tc.c.Reserve(tc.ctx, cfg, mount.Config{ReadOnly: cfg.ReadOnly}); err != nil {
					t.Fatalf("Reserve %s: %v", cfg.HostPath, err)
				}
			}

			dst := roundTrip(t, tc.c)
			assertControllerExactlyEqual(t, tc.c, dst)

			if dst.noWritableFileShares != tt.noWritableFileShares {
				t.Errorf("noWritableFileShares: want %v got %v", tt.noWritableFileShares, dst.noWritableFileShares)
			}
		})
	}
}

// TestRoundTrip_NameCounterPreserved checks the monotonic name allocator
// continues from the saved value, so post-resume names cannot collide with
// previously-restored shares.
func TestRoundTrip_NameCounterPreserved(t *testing.T) {
	t.Parallel()
	tc := newTestController(t, false)
	_, _ = tc.c.Reserve(tc.ctx, share.Config{HostPath: "/path/a"}, mount.Config{})
	_, _ = tc.c.Reserve(tc.ctx, share.Config{HostPath: "/path/b"}, mount.Config{})
	_, _ = tc.c.Reserve(tc.ctx, share.Config{HostPath: "/path/c"}, mount.Config{})
	if tc.c.nameCounter != 3 {
		t.Fatalf("precondition: nameCounter=%d", tc.c.nameCounter)
	}

	dst := roundTrip(t, tc.c)
	if dst.nameCounter != 3 {
		t.Errorf("nameCounter: want 3 got %d", dst.nameCounter)
	}

	// After Resume with a fresh mock set (modeling a cross-shim handoff
	// where the destination process owns brand-new vm/guest bindings), a
	// new reservation must use the next counter value.
	rtc, vm, guest := newTestMocks(t)
	dst.Resume(vm, guest)
	rtc.c = dst
	id, err := rtc.c.Reserve(rtc.ctx, share.Config{HostPath: "/path/d"}, mount.Config{})
	if err != nil {
		t.Fatalf("post-resume Reserve: %v", err)
	}
	if got := rtc.c.sharesByHostPath["/path/d"].Name(); got != "3" {
		t.Errorf("new share name: want %q got %q", "3", got)
	}
	if rtc.c.nameCounter != 4 {
		t.Errorf("nameCounter after new reserve: want 4 got %d", rtc.c.nameCounter)
	}
	if _, ok := rtc.c.reservations[id]; !ok {
		t.Error("new reservation missing from map")
	}
}

// TestRoundTrip_MappedShare covers a Reserved → Added → Mounted share, and
// verifies that a post-resume MapToGuest is idempotent (no host/guest calls
// re-issued, same guest path returned).
func TestRoundTrip_MappedShare(t *testing.T) {
	t.Parallel()
	tc := newTestController(t, false)
	id, _ := tc.c.Reserve(tc.ctx, share.Config{HostPath: "/host/m"}, mount.Config{})
	tc.vmAdd.EXPECT().AddPlan9(gomock.Any(), gomock.Any()).Return(nil)
	tc.guestMount.EXPECT().AddMappedDirectory(gomock.Any(), gomock.Any()).Return(nil)
	gp, err := tc.c.MapToGuest(tc.ctx, id)
	if err != nil {
		t.Fatalf("MapToGuest: %v", err)
	}

	dst := roundTrip(t, tc.c)
	assertControllerExactlyEqual(t, tc.c, dst)

	if got := dst.sharesByHostPath["/host/m"].State(); got != share.StateAdded {
		t.Errorf("share state after round-trip: want Added got %s", got)
	}

	rtc, vm, guest := newTestMocks(t)
	dst.Resume(vm, guest)
	rtc.c = dst
	got, err := rtc.c.MapToGuest(rtc.ctx, id)
	if err != nil {
		t.Fatalf("post-resume MapToGuest: %v", err)
	}
	if got != gp {
		t.Errorf("post-resume guest path: want %q got %q", gp, got)
	}
}

// TestRoundTrip_RefCountedShare covers two reservations on the same host path
// that are both mapped. After round-trip + Resume, the first UnmapFromGuest
// must NOT issue any guest/VM calls (refCount drops 2→1) and the second must
// issue both the guest unmount and the VM remove.
func TestRoundTrip_RefCountedShare(t *testing.T) {
	t.Parallel()
	tc := newTestController(t, false)

	id1, _ := tc.c.Reserve(tc.ctx, share.Config{HostPath: "/host/r"}, mount.Config{})
	id2, _ := tc.c.Reserve(tc.ctx, share.Config{HostPath: "/host/r"}, mount.Config{})
	tc.vmAdd.EXPECT().AddPlan9(gomock.Any(), gomock.Any()).Return(nil).Times(1)
	tc.guestMount.EXPECT().AddMappedDirectory(gomock.Any(), gomock.Any()).Return(nil).Times(1)
	if _, err := tc.c.MapToGuest(tc.ctx, id1); err != nil {
		t.Fatalf("MapToGuest id1: %v", err)
	}
	if _, err := tc.c.MapToGuest(tc.ctx, id2); err != nil {
		t.Fatalf("MapToGuest id2: %v", err)
	}

	dst := roundTrip(t, tc.c)
	assertControllerExactlyEqual(t, tc.c, dst)

	rtc, vm, guest := newTestMocks(t)
	dst.Resume(vm, guest)
	rtc.c = dst

	// First post-resume unmap: no host/guest calls expected.
	if err := rtc.c.UnmapFromGuest(rtc.ctx, id1); err != nil {
		t.Fatalf("first UnmapFromGuest: %v", err)
	}
	if len(rtc.c.sharesByHostPath) != 1 {
		t.Errorf("share should still exist; got %d shares", len(rtc.c.sharesByHostPath))
	}

	// Second post-resume unmap: last ref → guest unmount + VM remove.
	rtc.guestUnmount.EXPECT().RemoveMappedDirectory(gomock.Any(), gomock.Any()).Return(nil).Times(1)
	rtc.vmRemove.EXPECT().RemovePlan9(gomock.Any(), gomock.Any()).Return(nil).Times(1)
	if err := rtc.c.UnmapFromGuest(rtc.ctx, id2); err != nil {
		t.Fatalf("second UnmapFromGuest: %v", err)
	}
	if len(rtc.c.sharesByHostPath) != 0 || len(rtc.c.reservations) != 0 {
		t.Errorf("expected empty maps after final unmap, got %d shares / %d reservations",
			len(rtc.c.sharesByHostPath), len(rtc.c.reservations))
	}
}

// TestRoundTrip_InvalidShareDrains covers a share whose AddToVM failed and is
// stuck in StateInvalid with outstanding reservations. After migration +
// Resume, draining the reservations must NOT call vm.RemovePlan9 (the share
// was never added) and must clean up.
func TestRoundTrip_InvalidShareDrains(t *testing.T) {
	t.Parallel()
	tc := newTestController(t, false)

	id1, _ := tc.c.Reserve(tc.ctx, share.Config{HostPath: "/host/inv"}, mount.Config{})
	id2, _ := tc.c.Reserve(tc.ctx, share.Config{HostPath: "/host/inv"}, mount.Config{})
	tc.vmAdd.EXPECT().AddPlan9(gomock.Any(), gomock.Any()).Return(errVMAdd)
	if _, err := tc.c.MapToGuest(tc.ctx, id1); err == nil {
		t.Fatal("expected MapToGuest to fail")
	}

	// Sanity: the share is in StateInvalid before round-trip.
	if got := tc.c.sharesByHostPath["/host/inv"].State(); got != share.StateInvalid {
		t.Fatalf("precondition: share state want Invalid got %s", got)
	}

	dst := roundTrip(t, tc.c)
	assertControllerExactlyEqual(t, tc.c, dst)

	if got := dst.sharesByHostPath["/host/inv"].State(); got != share.StateInvalid {
		t.Errorf("share state after round-trip: want Invalid got %s", got)
	}

	rtc, vm, guest := newTestMocks(t)
	dst.Resume(vm, guest)
	rtc.c = dst

	// Neither caller should trigger a guest unmount or VM remove — the share
	// never reached the VM and no guest mount was established. The fresh
	// mocks have no expectations recorded, so any call would fail the test.
	if err := rtc.c.UnmapFromGuest(rtc.ctx, id1); err != nil {
		t.Fatalf("first UnmapFromGuest: %v", err)
	}
	if err := rtc.c.UnmapFromGuest(rtc.ctx, id2); err != nil {
		t.Fatalf("second UnmapFromGuest: %v", err)
	}
	if len(rtc.c.sharesByHostPath) != 0 || len(rtc.c.reservations) != 0 {
		t.Errorf("expected clean state, got %d shares / %d reservations",
			len(rtc.c.sharesByHostPath), len(rtc.c.reservations))
	}
}

// TestRoundTrip_InvalidMountDrains is the mount-layer counterpart to
// [TestRoundTrip_InvalidShareDrains]: the share reaches StateAdded but the
// guest mount call fails, leaving the mount in StateInvalid with two
// outstanding reservations. After migration + Resume, draining must NOT
// re-issue the guest unmount (no guest state was established) but MUST
// issue vm.RemovePlan9 on the last drain (the share *was* added to the VM).
func TestRoundTrip_InvalidMountDrains(t *testing.T) {
	t.Parallel()
	tc := newTestController(t, false)

	id1, _ := tc.c.Reserve(tc.ctx, share.Config{HostPath: "/host/badmount"}, mount.Config{})
	id2, _ := tc.c.Reserve(tc.ctx, share.Config{HostPath: "/host/badmount"}, mount.Config{})
	tc.vmAdd.EXPECT().AddPlan9(gomock.Any(), gomock.Any()).Return(nil)
	tc.guestMount.EXPECT().AddMappedDirectory(gomock.Any(), gomock.Any()).Return(errMount)
	if _, err := tc.c.MapToGuest(tc.ctx, id1); err == nil {
		t.Fatal("expected MapToGuest to fail at guest mount")
	}

	// Sanity: share is StateAdded, mount is StateInvalid before round-trip.
	sh := tc.c.sharesByHostPath["/host/badmount"]
	if got := sh.State(); got != share.StateAdded {
		t.Fatalf("precondition: share state want Added got %s", got)
	}

	dst := roundTrip(t, tc.c)
	assertControllerExactlyEqual(t, tc.c, dst)

	if got := dst.sharesByHostPath["/host/badmount"].State(); got != share.StateAdded {
		t.Errorf("share state after round-trip: want Added got %s", got)
	}

	rtc, vm, guest := newTestMocks(t)
	dst.Resume(vm, guest)
	rtc.c = dst

	// First drain: refCount 2→1, no guest/VM calls (mount in StateInvalid,
	// share still has an active mount).
	if err := rtc.c.UnmapFromGuest(rtc.ctx, id1); err != nil {
		t.Fatalf("first UnmapFromGuest: %v", err)
	}
	if len(rtc.c.sharesByHostPath) != 1 {
		t.Errorf("share should still exist; got %d shares", len(rtc.c.sharesByHostPath))
	}

	// Second drain: refCount 1→0, mount detaches; share is StateAdded so
	// vm.RemovePlan9 IS issued. No guest unmount (mount never reached the
	// guest).
	rtc.vmRemove.EXPECT().RemovePlan9(gomock.Any(), gomock.Any()).Return(nil).Times(1)
	if err := rtc.c.UnmapFromGuest(rtc.ctx, id2); err != nil {
		t.Fatalf("second UnmapFromGuest: %v", err)
	}
	if len(rtc.c.sharesByHostPath) != 0 || len(rtc.c.reservations) != 0 {
		t.Errorf("expected clean state, got %d shares / %d reservations",
			len(rtc.c.sharesByHostPath), len(rtc.c.reservations))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Migration-state guard tests
// ─────────────────────────────────────────────────────────────────────────────

// TestMigrating_GuardThenResume verifies that the imported controller rejects
// public Reserve/MapToGuest/UnmapFromGuest until Resume binds the live
// host/guest interfaces, and that operations succeed once it does.
func TestMigrating_GuardThenResume(t *testing.T) {
	t.Parallel()
	tc := newTestController(t, false)
	id, _ := tc.c.Reserve(tc.ctx, share.Config{HostPath: "/host/g"}, mount.Config{})

	dst := roundTrip(t, tc.c)

	if _, err := dst.Reserve(tc.ctx, share.Config{HostPath: "/h/new"}, mount.Config{}); err == nil {
		t.Error("Reserve should fail while migrating")
	}
	if _, err := dst.MapToGuest(tc.ctx, id); err == nil {
		t.Error("MapToGuest should fail while migrating")
	}
	if err := dst.UnmapFromGuest(tc.ctx, id); err == nil {
		t.Error("UnmapFromGuest should fail while migrating")
	}

	rtc, vm, guest := newTestMocks(t)
	dst.Resume(vm, guest)
	rtc.c = dst
	if rtc.c.isMigrating {
		t.Error("isMigrating should be false after Resume")
	}
	if rtc.c.vmPlan9 == nil || rtc.c.guest == nil {
		t.Error("Resume must bind vm/guest interfaces")
	}
	if _, err := rtc.c.Reserve(rtc.ctx, share.Config{HostPath: "/h/post"}, mount.Config{}); err != nil {
		t.Errorf("post-resume Reserve: %v", err)
	}
}

// TestEndToEnd_SaveImportResumeContinuesLifecycle exercises a full cross-shim
// workflow: build a controller with two shares (one fully mapped, one only
// reserved), serialize it, rehydrate on a fresh controller with new mocks,
// resume, and complete the lifecycle on the destination side.
func TestEndToEnd_SaveImportResumeContinuesLifecycle(t *testing.T) {
	t.Parallel()
	src := newTestController(t, false)

	// Share #1: fully mapped.
	id1, _ := src.c.Reserve(src.ctx, share.Config{HostPath: "/h/mapped"}, mount.Config{})
	src.vmAdd.EXPECT().AddPlan9(gomock.Any(), gomock.Any()).Return(nil)
	src.guestMount.EXPECT().AddMappedDirectory(gomock.Any(), gomock.Any()).Return(nil)
	gp1, err := src.c.MapToGuest(src.ctx, id1)
	if err != nil {
		t.Fatalf("MapToGuest id1: %v", err)
	}

	// Share #2: only reserved.
	id2, _ := src.c.Reserve(src.ctx, share.Config{HostPath: "/h/reserved", ReadOnly: true}, mount.Config{ReadOnly: true})

	// Round-trip onto a fresh controller and bind new mocks (modeling the
	// destination shim owning its own vm/guest interface bindings).
	dst := roundTrip(t, src.c)
	assertControllerExactlyEqual(t, src.c, dst)
	rtc, vm, guest := newTestMocks(t)
	dst.Resume(vm, guest)
	rtc.c = dst

	// id1: idempotent MapToGuest (already mounted) returns the same guest path
	// without re-issuing any host/guest call.
	gp1Again, err := rtc.c.MapToGuest(rtc.ctx, id1)
	if err != nil {
		t.Fatalf("post-resume MapToGuest id1: %v", err)
	}
	if gp1Again != gp1 {
		t.Errorf("guest path mismatch post-resume: want %q got %q", gp1, gp1Again)
	}

	// id2: complete the lifecycle by mapping it now on the destination.
	rtc.vmAdd.EXPECT().AddPlan9(gomock.Any(), gomock.Any()).Return(nil)
	rtc.guestMount.EXPECT().AddMappedDirectory(gomock.Any(), gomock.Any()).Return(nil)
	if _, err := rtc.c.MapToGuest(rtc.ctx, id2); err != nil {
		t.Fatalf("post-resume MapToGuest id2: %v", err)
	}

	// Tear both down.
	rtc.guestUnmount.EXPECT().RemoveMappedDirectory(gomock.Any(), gomock.Any()).Return(nil).Times(2)
	rtc.vmRemove.EXPECT().RemovePlan9(gomock.Any(), gomock.Any()).Return(nil).Times(2)
	if err := rtc.c.UnmapFromGuest(rtc.ctx, id1); err != nil {
		t.Fatalf("post-resume UnmapFromGuest id1: %v", err)
	}
	if err := rtc.c.UnmapFromGuest(rtc.ctx, id2); err != nil {
		t.Fatalf("post-resume UnmapFromGuest id2: %v", err)
	}
	if len(rtc.c.reservations) != 0 || len(rtc.c.sharesByHostPath) != 0 {
		t.Errorf("expected empty controller, got %d reservations / %d shares",
			len(rtc.c.reservations), len(rtc.c.sharesByHostPath))
	}
}
