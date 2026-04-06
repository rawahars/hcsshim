//go:build windows

package container

import (
	"errors"
	"testing"

	"github.com/Microsoft/go-winio/pkg/guid"
	"go.uber.org/mock/gomock"

	"github.com/Microsoft/hcsshim/internal/builder/container/mocks"
)

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

// testController bundles the mock reservers used by every Release test.
type testController struct {
	scsi *mocks.MockSCSIReserver
	p9   *mocks.MockPlan9Reserver
	vpci *mocks.MockVPCIReserver
}

// newTestController creates a parallel-safe testController with fresh mocks.
func newTestController(t *testing.T) *testController {
	t.Helper()
	t.Parallel()

	ctrl := gomock.NewController(t)
	return &testController{
		scsi: mocks.NewMockSCSIReserver(ctrl),
		p9:   mocks.NewMockPlan9Reserver(ctrl),
		vpci: mocks.NewMockVPCIReserver(ctrl),
	}
}

// newGUID is a test helper that generates a random GUID and fails the test on error.
func newGUID(t *testing.T) guid.GUID {
	t.Helper()
	id, err := guid.NewV4()
	if err != nil {
		t.Fatalf("failed to generate GUID: %v", err)
	}
	return id
}

// ─────────────────────────────────────────────────────────────────────────────
// Release — nil receiver
// ─────────────────────────────────────────────────────────────────────────────

// TestRelease_NilPlan verifies that Release on a nil *ResourcePlan is a no-op
// and does not panic.
func TestRelease_NilPlan(t *testing.T) {
	tc := newTestController(t)

	// No expectations — nothing should be called.
	var rp *ResourcePlan
	rp.Release(t.Context(), tc.scsi, tc.p9, tc.vpci)
}

// ─────────────────────────────────────────────────────────────────────────────
// Release — empty plan
// ─────────────────────────────────────────────────────────────────────────────

// TestRelease_EmptyPlan verifies that Release on an empty (but non-nil)
// ResourcePlan is a no-op and does not call any reserver methods.
func TestRelease_EmptyPlan(t *testing.T) {
	tc := newTestController(t)

	(&ResourcePlan{}).Release(t.Context(), tc.scsi, tc.p9, tc.vpci)
}

// ─────────────────────────────────────────────────────────────────────────────
// Release — Plan9 shares only
// ─────────────────────────────────────────────────────────────────────────────

// TestRelease_Plan9SharesOnly verifies that Release unmaps all Plan9 shares
// when no other resource types are present.
func TestRelease_Plan9SharesOnly(t *testing.T) {
	tc := newTestController(t)

	id1, id2 := newGUID(t), newGUID(t)

	gomock.InOrder(
		tc.p9.EXPECT().UnmapFromGuest(gomock.Any(), id1).Return(nil),
		tc.p9.EXPECT().UnmapFromGuest(gomock.Any(), id2).Return(nil),
	)

	rp := &ResourcePlan{
		Plan9: []guid.GUID{id1, id2},
	}
	rp.Release(t.Context(), tc.scsi, tc.p9, tc.vpci)
}

// ─────────────────────────────────────────────────────────────────────────────
// Release — VPCI devices only
// ─────────────────────────────────────────────────────────────────────────────

// TestRelease_VPCIDevicesOnly verifies that Release removes all vPCI devices
// when no other resource types are present.
func TestRelease_VPCIDevicesOnly(t *testing.T) {
	tc := newTestController(t)

	id1, id2 := newGUID(t), newGUID(t)

	gomock.InOrder(
		tc.vpci.EXPECT().RemoveFromVM(gomock.Any(), id1).Return(nil),
		tc.vpci.EXPECT().RemoveFromVM(gomock.Any(), id2).Return(nil),
	)

	rp := &ResourcePlan{
		Devices: []guid.GUID{id1, id2},
	}
	rp.Release(t.Context(), tc.scsi, tc.p9, tc.vpci)
}

// ─────────────────────────────────────────────────────────────────────────────
// Release — SCSI mounts only (non-layer)
// ─────────────────────────────────────────────────────────────────────────────

// TestRelease_SCSIMountsOnly verifies that Release unmaps all non-layer SCSI
// mounts when no other resource types are present.
func TestRelease_SCSIMountsOnly(t *testing.T) {
	tc := newTestController(t)

	id1, id2 := newGUID(t), newGUID(t)

	gomock.InOrder(
		tc.scsi.EXPECT().UnmapFromGuest(gomock.Any(), id1).Return(nil),
		tc.scsi.EXPECT().UnmapFromGuest(gomock.Any(), id2).Return(nil),
	)

	rp := &ResourcePlan{
		SCSI: []guid.GUID{id1, id2},
	}
	rp.Release(t.Context(), tc.scsi, tc.p9, tc.vpci)
}

// ─────────────────────────────────────────────────────────────────────────────
// Release — SCSI layers only (scratch + read-only)
// ─────────────────────────────────────────────────────────────────────────────

// TestRelease_SCSILayersOnly verifies that Release unmaps the scratch layer and
// all read-only layers when only SCSILayers are present.
func TestRelease_SCSILayersOnly(t *testing.T) {
	tc := newTestController(t)

	scratchID := newGUID(t)
	roID1, roID2 := newGUID(t), newGUID(t)

	gomock.InOrder(
		// Scratch layer release.
		tc.scsi.EXPECT().UnmapFromGuest(gomock.Any(), scratchID).Return(nil),
		// Read-only layer releases.
		tc.scsi.EXPECT().UnmapFromGuest(gomock.Any(), roID1).Return(nil),
		tc.scsi.EXPECT().UnmapFromGuest(gomock.Any(), roID2).Return(nil),
	)

	rp := &ResourcePlan{
		SCSILayers: &SCSILayerPlan{
			Scratch: MountReservation{ID: scratchID, GuestPath: "/scratch"},
			ROLayers: []MountReservation{
				{ID: roID1, GuestPath: "/layer1"},
				{ID: roID2, GuestPath: "/layer2"},
			},
		},
	}
	rp.Release(t.Context(), tc.scsi, tc.p9, tc.vpci)
}

// ─────────────────────────────────────────────────────────────────────────────
// Release — SCSI layers with zero-GUID scratch (never reserved)
// ─────────────────────────────────────────────────────────────────────────────

// TestRelease_SCSILayers_ZeroScratch verifies that Release skips the scratch
// layer when its GUID is the zero value (never reserved) but still releases
// read-only layers.
func TestRelease_SCSILayers_ZeroScratch(t *testing.T) {
	tc := newTestController(t)

	roID := newGUID(t)

	// Only the read-only layer should be released — scratch is zero GUID.
	tc.scsi.EXPECT().UnmapFromGuest(gomock.Any(), roID).Return(nil)

	rp := &ResourcePlan{
		SCSILayers: &SCSILayerPlan{
			Scratch: MountReservation{}, // zero GUID — never reserved.
			ROLayers: []MountReservation{
				{ID: roID, GuestPath: "/layer1"},
			},
		},
	}
	rp.Release(t.Context(), tc.scsi, tc.p9, tc.vpci)
}

// ─────────────────────────────────────────────────────────────────────────────
// Release — full plan (all resource types)
// ─────────────────────────────────────────────────────────────────────────────

// TestRelease_FullPlan verifies that Release cleans up every resource type
// (Plan9, vPCI, non-layer SCSI, scratch, and read-only layers) in a single call.
func TestRelease_FullPlan(t *testing.T) {
	tc := newTestController(t)

	plan9ID := newGUID(t)
	vpciID := newGUID(t)
	scsiMountID := newGUID(t)
	scratchID := newGUID(t)
	roID := newGUID(t)

	gomock.InOrder(
		// Plan9 share.
		tc.p9.EXPECT().UnmapFromGuest(gomock.Any(), plan9ID).Return(nil),
		// vPCI device.
		tc.vpci.EXPECT().RemoveFromVM(gomock.Any(), vpciID).Return(nil),
		// Non-layer SCSI mount.
		tc.scsi.EXPECT().UnmapFromGuest(gomock.Any(), scsiMountID).Return(nil),
		// Scratch layer.
		tc.scsi.EXPECT().UnmapFromGuest(gomock.Any(), scratchID).Return(nil),
		// Read-only layer.
		tc.scsi.EXPECT().UnmapFromGuest(gomock.Any(), roID).Return(nil),
	)

	rp := &ResourcePlan{
		Plan9:   []guid.GUID{plan9ID},
		Devices: []guid.GUID{vpciID},
		SCSI:    []guid.GUID{scsiMountID},
		SCSILayers: &SCSILayerPlan{
			Scratch:  MountReservation{ID: scratchID, GuestPath: "/scratch"},
			ROLayers: []MountReservation{{ID: roID, GuestPath: "/layer1"}},
		},
	}
	rp.Release(t.Context(), tc.scsi, tc.p9, tc.vpci)
}

// ─────────────────────────────────────────────────────────────────────────────
// Release — errors are logged but do not stop cleanup
// ─────────────────────────────────────────────────────────────────────────────

// TestRelease_ErrorsDoNotStopCleanup verifies that when one reserver returns an
// error, Release continues releasing all remaining resources rather than aborting.
func TestRelease_ErrorsDoNotStopCleanup(t *testing.T) {
	tc := newTestController(t)

	plan9ID := newGUID(t)
	vpciID := newGUID(t)
	scsiMountID := newGUID(t)
	scratchID := newGUID(t)
	roID := newGUID(t)

	errRelease := errors.New("release failed")

	gomock.InOrder(
		// Plan9 fails, but cleanup must continue.
		tc.p9.EXPECT().UnmapFromGuest(gomock.Any(), plan9ID).Return(errRelease),
		// vPCI fails, but cleanup must continue.
		tc.vpci.EXPECT().RemoveFromVM(gomock.Any(), vpciID).Return(errRelease),
		// Non-layer SCSI fails, but cleanup must continue.
		tc.scsi.EXPECT().UnmapFromGuest(gomock.Any(), scsiMountID).Return(errRelease),
		// Scratch fails, but cleanup must continue.
		tc.scsi.EXPECT().UnmapFromGuest(gomock.Any(), scratchID).Return(errRelease),
		// Read-only layer must still be released.
		tc.scsi.EXPECT().UnmapFromGuest(gomock.Any(), roID).Return(nil),
	)

	rp := &ResourcePlan{
		Plan9:   []guid.GUID{plan9ID},
		Devices: []guid.GUID{vpciID},
		SCSI:    []guid.GUID{scsiMountID},
		SCSILayers: &SCSILayerPlan{
			Scratch:  MountReservation{ID: scratchID, GuestPath: "/scratch"},
			ROLayers: []MountReservation{{ID: roID, GuestPath: "/layer1"}},
		},
	}
	rp.Release(t.Context(), tc.scsi, tc.p9, tc.vpci)
}

// ─────────────────────────────────────────────────────────────────────────────
// Release — SCSILayers with only zero-GUID scratch and empty ROLayers
// ─────────────────────────────────────────────────────────────────────────────

// TestRelease_SCSILayers_ZeroScratch_EmptyROLayers verifies that Release handles
// a non-nil SCSILayerPlan where the scratch is zero GUID and the ROLayers slice
// is empty — nothing should be released for layers.
func TestRelease_SCSILayers_ZeroScratch_EmptyROLayers(t *testing.T) {
	tc := newTestController(t)

	// No expectations — nothing should be called on any mock.
	rp := &ResourcePlan{
		SCSILayers: &SCSILayerPlan{
			Scratch:  MountReservation{}, // zero GUID.
			ROLayers: nil,
		},
	}
	rp.Release(t.Context(), tc.scsi, tc.p9, tc.vpci)
}
