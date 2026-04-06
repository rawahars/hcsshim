//go:build windows && lcow

package lcow

import (
	"errors"
	"testing"

	"github.com/Microsoft/hcsshim/internal/builder/container/mocks"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/opencontainers/runtime-spec/specs-go"
	"go.uber.org/mock/gomock"
)

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

// reserveTestController bundles mock reservers for ReserveAll tests.
type reserveTestController struct {
	scsi *mocks.MockSCSIReserver
	p9   *mocks.MockPlan9Reserver
	vpci *mocks.MockVPCIReserver
}

// newReserveTestController creates a parallel-safe reserveTestController.
func newReserveTestController(t *testing.T) *reserveTestController {
	t.Helper()
	t.Parallel()

	ctrl := gomock.NewController(t)
	return &reserveTestController{
		scsi: mocks.NewMockSCSIReserver(ctrl),
		p9:   mocks.NewMockPlan9Reserver(ctrl),
		vpci: mocks.NewMockVPCIReserver(ctrl),
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ReserveAll — first RO layer fails, no cleanup needed
// ─────────────────────────────────────────────────────────────────────────────

// TestReserveAll_FirstROLayerFails verifies that when the only read-only layer
// reservation fails (nothing was successfully reserved), the deferred cleanup
// runs without making any UnmapFromGuest calls.
func TestReserveAll_FirstROLayerFails(t *testing.T) {
	tc := newReserveTestController(t)

	layerDir := createTempDirWithFile(t, "layer.vhd")
	scratchDir := createTempDirWithFile(t, "sandbox.vhdx")

	spec := &specs.Spec{
		Windows: &specs.Windows{
			LayerFolders: []string{layerDir, scratchDir},
		},
	}
	cfg := &ReserveConfig{
		VMID:        "vm-1",
		PodID:       "pod-1",
		ContainerID: "ctr-1",
	}

	// First (and only) RO layer fails — no successful reservation to clean up.
	tc.scsi.EXPECT().Reserve(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(guid.GUID{}, "", errors.New("scsi bus full"))

	plan, err := ReserveAll(t.Context(), tc.scsi, tc.p9, tc.vpci, spec, cfg)
	if err == nil {
		t.Fatal("expected error from RO layer reservation failure")
	}
	if plan != nil {
		t.Errorf("expected nil plan on failure, got %+v", plan)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ReserveAll — partial RO layer failure triggers cleanup
// ─────────────────────────────────────────────────────────────────────────────

// TestReserveAll_ROLayerFailureTriggersCleanup verifies that when the second
// read-only layer reservation fails, the first successfully reserved layer
// is released via the deferred cleanup.
func TestReserveAll_ROLayerFailureTriggersCleanup(t *testing.T) {
	tc := newReserveTestController(t)

	layerDir1 := createTempDirWithFile(t, "layer.vhd")
	layerDir2 := createTempDirWithFile(t, "layer.vhd")
	scratchDir := createTempDirWithFile(t, "sandbox.vhdx")

	spec := &specs.Spec{
		Windows: &specs.Windows{
			LayerFolders: []string{layerDir1, layerDir2, scratchDir},
		},
	}
	cfg := &ReserveConfig{
		VMID:        "vm-1",
		PodID:       "pod-1",
		ContainerID: "ctr-1",
	}

	reservationID := newGUID(t)

	gomock.InOrder(
		// Phase 1: First RO layer reserved successfully.
		tc.scsi.EXPECT().Reserve(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(reservationID, "/layer1", nil),
		// Phase 1: Second RO layer fails.
		tc.scsi.EXPECT().Reserve(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(guid.GUID{}, "", errors.New("scsi bus full")),
		// Cleanup (defer): first RO layer released.
		tc.scsi.EXPECT().UnmapFromGuest(gomock.Any(), reservationID).Return(nil),
	)

	plan, err := ReserveAll(t.Context(), tc.scsi, tc.p9, tc.vpci, spec, cfg)
	if err == nil {
		t.Fatal("expected error from RO layer reservation failure")
	}
	if plan != nil {
		t.Errorf("expected nil plan on failure, got %+v", plan)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ReserveAll — scratch Reserve failure triggers cleanup of RO layers
// ─────────────────────────────────────────────────────────────────────────────

// TestReserveAll_ScratchFailureReleasesROLayers verifies that when all
// read-only layers are reserved but the scratch layer Reserve fails,
// the deferred cleanup releases every RO layer.
func TestReserveAll_ScratchFailureReleasesROLayers(t *testing.T) {
	tc := newReserveTestController(t)

	layerDir := createTempDirWithFile(t, "layer.vhd")
	scratchDir := createTempDirWithFile(t, "sandbox.vhdx")

	spec := &specs.Spec{
		Windows: &specs.Windows{
			LayerFolders: []string{layerDir, scratchDir},
		},
	}
	cfg := &ReserveConfig{
		VMID:        "test-vm",
		PodID:       "pod-1",
		ContainerID: "ctr-1",
	}

	reservationID := newGUID(t)

	gomock.InOrder(
		// Phase 1: Single RO layer reserved successfully.
		tc.scsi.EXPECT().Reserve(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(reservationID, "/layer1", nil),
		// Phase 1: Scratch layer Reserve fails.
		tc.scsi.EXPECT().Reserve(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(guid.GUID{}, "", errors.New("no free scsi slots")),
		// Cleanup (defer): RO layer released after scratch reservation failure.
		tc.scsi.EXPECT().UnmapFromGuest(gomock.Any(), reservationID).Return(nil),
	)

	plan, err := ReserveAll(t.Context(), tc.scsi, tc.p9, tc.vpci, spec, cfg)
	if err == nil {
		t.Fatal("expected error from scratch layer reservation failure")
	}
	if plan != nil {
		t.Errorf("expected nil plan on failure, got %+v", plan)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ReserveAll — full success sets spec root path
// ─────────────────────────────────────────────────────────────────────────────

// TestReserveAll_FullSuccess verifies the complete success path: all layers
// are reserved, the spec root path is set, and the returned plan contains
// the expected reservations.
func TestReserveAll_FullSuccess(t *testing.T) {
	tc := newReserveTestController(t)

	layerDir := createTempDirWithFile(t, "layer.vhd")
	scratchDir := createTempDirWithFile(t, "sandbox.vhdx")

	spec := &specs.Spec{
		Windows: &specs.Windows{
			LayerFolders: []string{layerDir, scratchDir},
		},
	}
	cfg := &ReserveConfig{
		VMID:        "test-vm",
		PodID:       "pod-1",
		ContainerID: "ctr-1",
	}

	roReservationID := newGUID(t)
	scratchReservationID := newGUID(t)

	gomock.InOrder(
		// Phase 1: RO layer.
		tc.scsi.EXPECT().Reserve(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(roReservationID, "/layer1", nil),
		// Phase 1: Scratch.
		tc.scsi.EXPECT().Reserve(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(scratchReservationID, "/scratch/mount", nil),
	)
	// Phase 2: No mounts (spec.Mounts is nil).
	// Phase 3: No devices (spec.Windows.Devices is nil).

	plan, err := ReserveAll(t.Context(), tc.scsi, tc.p9, tc.vpci, spec, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan == nil {
		t.Fatal("expected non-nil plan")
	}

	// Verify spec root path was set (auto-created since spec.Root was nil).
	expectedRootfs := "/run/gcs/pods/pod-1/ctr-1/rootfs"
	if spec.Root == nil {
		t.Fatal("expected spec.Root to be auto-created")
	}
	if spec.Root.Path != expectedRootfs {
		t.Errorf("expected spec.Root.Path = %q, got %q", expectedRootfs, spec.Root.Path)
	}

	// Verify the plan references.
	if plan.SCSILayers == nil {
		t.Fatal("expected non-nil SCSILayers in plan")
	}
	if len(plan.SCSILayers.ROLayers) != 1 {
		t.Fatalf("expected 1 RO layer, got %d", len(plan.SCSILayers.ROLayers))
	}
	if plan.SCSILayers.ROLayers[0].ID != roReservationID {
		t.Errorf("expected RO layer ID %s, got %s", roReservationID, plan.SCSILayers.ROLayers[0].ID)
	}
	if plan.SCSILayers.Scratch.ID != scratchReservationID {
		t.Errorf("expected scratch ID %s, got %s", scratchReservationID, plan.SCSILayers.Scratch.ID)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ReserveAll — existing spec.Root is preserved
// ─────────────────────────────────────────────────────────────────────────────

// TestReserveAll_ExistingSpecRoot verifies that when spec.Root is already
// non-nil, only the Path field is overwritten with the layer plan's rootfs.
func TestReserveAll_ExistingSpecRoot(t *testing.T) {
	tc := newReserveTestController(t)

	layerDir := createTempDirWithFile(t, "layer.vhd")
	scratchDir := createTempDirWithFile(t, "sandbox.vhdx")

	spec := &specs.Spec{
		Root: &specs.Root{
			Path:     "/old/rootfs",
			Readonly: true,
		},
		Windows: &specs.Windows{
			LayerFolders: []string{layerDir, scratchDir},
		},
	}
	cfg := &ReserveConfig{
		VMID:        "test-vm",
		PodID:       "pod-1",
		ContainerID: "ctr-1",
	}

	gomock.InOrder(
		tc.scsi.EXPECT().Reserve(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(newGUID(t), "/layer1", nil),
		tc.scsi.EXPECT().Reserve(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(newGUID(t), "/scratch", nil),
	)

	_, err := ReserveAll(t.Context(), tc.scsi, tc.p9, tc.vpci, spec, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedRootfs := "/run/gcs/pods/pod-1/ctr-1/rootfs"
	if spec.Root.Path != expectedRootfs {
		t.Errorf("expected spec.Root.Path = %q, got %q", expectedRootfs, spec.Root.Path)
	}
	// The Readonly field should remain unchanged.
	if !spec.Root.Readonly {
		t.Error("expected spec.Root.Readonly to remain true")
	}
}
