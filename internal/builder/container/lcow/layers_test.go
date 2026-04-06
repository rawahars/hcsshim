//go:build windows && lcow

package lcow

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Microsoft/go-winio/pkg/guid"
	"go.uber.org/mock/gomock"

	"github.com/Microsoft/hcsshim/internal/builder/container/mocks"
	"github.com/Microsoft/hcsshim/internal/controller/device/scsi/disk"
	scsiMount "github.com/Microsoft/hcsshim/internal/controller/device/scsi/mount"
	"github.com/Microsoft/hcsshim/internal/layers"
)

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

// createTempDirWithFile creates a temporary directory containing a single file
// with the given name. The directory path is returned.
func createTempDirWithFile(t *testing.T, fileName string) string {
	t.Helper()
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, fileName))
	if err != nil {
		t.Fatalf("failed to create %s: %v", fileName, err)
	}
	_ = f.Close()
	return dir
}

// ─────────────────────────────────────────────────────────────────────────────
// reserveReadonlyLayer — success
// ─────────────────────────────────────────────────────────────────────────────

// TestReserveReadonlyLayer_Success verifies that a valid layer file is resolved
// and reserved with the correct SCSI disk and mount configuration.
func TestReserveReadonlyLayer_Success(t *testing.T) {
	t.Parallel()
	scsi := mocks.NewMockSCSIReserver(gomock.NewController(t))

	layerDir := createTempDirWithFile(t, "layer.vhd")
	vhdPath := filepath.Join(layerDir, "layer.vhd")

	reservationID := newGUID(t)
	expectedGuestPath := "/dev/sda"

	// Verify the mount config is passed exactly: read-only, no partition, "ro" option.
	scsi.EXPECT().Reserve(
		gomock.Any(),
		gomock.AssignableToTypeOf(disk.Config{}),
		scsiMount.Config{
			ReadOnly: true,
			Options:  []string{"ro"},
		},
	).DoAndReturn(func(_ context.Context, diskCfg disk.Config, _ scsiMount.Config) (guid.GUID, string, error) {
		if diskCfg.HostPath == "" {
			t.Error("expected non-empty host path in disk config")
		}
		if !diskCfg.ReadOnly {
			t.Error("expected disk config ReadOnly to be true")
		}
		if diskCfg.Type != disk.TypeVirtualDisk {
			t.Errorf("expected disk type %s, got %s", disk.TypeVirtualDisk, diskCfg.Type)
		}
		return reservationID, expectedGuestPath, nil
	})

	layer := &layers.LCOWLayer{VHDPath: vhdPath}
	gotID, gotPath, err := reserveReadonlyLayer(t.Context(), scsi, layer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotID != reservationID {
		t.Errorf("expected reservation ID %s, got %s", reservationID, gotID)
	}
	if gotPath != expectedGuestPath {
		t.Errorf("expected guest path %q, got %q", expectedGuestPath, gotPath)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// reserveReadonlyLayer — with partition
// ─────────────────────────────────────────────────────────────────────────────

// TestReserveReadonlyLayer_WithPartition verifies that the partition index from
// the LCOWLayer is forwarded to the SCSI mount configuration.
func TestReserveReadonlyLayer_WithPartition(t *testing.T) {
	t.Parallel()
	scsi := mocks.NewMockSCSIReserver(gomock.NewController(t))

	layerDir := createTempDirWithFile(t, "layer.vhd")
	vhdPath := filepath.Join(layerDir, "layer.vhd")

	reservationID := newGUID(t)

	scsi.EXPECT().Reserve(
		gomock.Any(),
		gomock.Any(),
		scsiMount.Config{
			Partition: 3,
			ReadOnly:  true,
			Options:   []string{"ro"},
		},
	).Return(reservationID, "/dev/sda3", nil)

	layer := &layers.LCOWLayer{VHDPath: vhdPath, Partition: 3}
	gotID, _, err := reserveReadonlyLayer(t.Context(), scsi, layer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotID != reservationID {
		t.Errorf("expected reservation ID %s, got %s", reservationID, gotID)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// reserveReadonlyLayer — non-existent path
// ─────────────────────────────────────────────────────────────────────────────

// TestReserveReadonlyLayer_BadPath verifies that a non-existent VHD path
// returns an error from fs.ResolvePath without calling Reserve.
func TestReserveReadonlyLayer_BadPath(t *testing.T) {
	t.Parallel()
	scsi := mocks.NewMockSCSIReserver(gomock.NewController(t))

	// No Reserve expectations — Reserve must not be called.
	layer := &layers.LCOWLayer{VHDPath: `C:\nonexistent\path\layer.vhd`}
	_, _, err := reserveReadonlyLayer(t.Context(), scsi, layer)
	if err == nil {
		t.Fatal("expected error for non-existent VHD path")
	}
	if !strings.Contains(err.Error(), "resolve symlinks") {
		t.Errorf("expected error about resolving symlinks, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// reserveReadonlyLayer — reserve failure
// ─────────────────────────────────────────────────────────────────────────────

// TestReserveReadonlyLayer_ReserveFailure verifies that an error from
// scsiReserver.Reserve is propagated with wrapping context.
func TestReserveReadonlyLayer_ReserveFailure(t *testing.T) {
	t.Parallel()
	scsi := mocks.NewMockSCSIReserver(gomock.NewController(t))

	layerDir := createTempDirWithFile(t, "layer.vhd")
	vhdPath := filepath.Join(layerDir, "layer.vhd")

	scsi.EXPECT().Reserve(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(guid.GUID{}, "", errors.New("no free scsi slots"))

	layer := &layers.LCOWLayer{VHDPath: vhdPath}
	_, _, err := reserveReadonlyLayer(t.Context(), scsi, layer)
	if err == nil {
		t.Fatal("expected error from Reserve failure")
	}
	if !strings.Contains(err.Error(), "reserve scsi slot") {
		t.Errorf("expected wrapped error about reserving scsi slot, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// reserveScratchLayer — non-existent path
// ─────────────────────────────────────────────────────────────────────────────

// TestReserveScratchLayer_BadPath verifies that a non-existent scratch VHD
// path returns an error from fs.ResolvePath without calling GrantVmAccess
// or Reserve.
func TestReserveScratchLayer_BadPath(t *testing.T) {
	t.Parallel()
	scsi := mocks.NewMockSCSIReserver(gomock.NewController(t))

	// No Reserve expectations.
	_, _, err := reserveScratchLayer(t.Context(), scsi, "test-vm", `C:\nonexistent\sandbox.vhdx`, false)
	if err == nil {
		t.Fatal("expected error for non-existent scratch VHD path")
	}
	if !strings.Contains(err.Error(), "resolve symlinks") {
		t.Errorf("expected error about resolving symlinks, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// reserveScratchLayer — success with encryption disabled
// ─────────────────────────────────────────────────────────────────────────────

// TestReserveScratchLayer_Success verifies that reserveScratchLayer resolves
// the scratch VHD path, grants VM access, and reserves a SCSI slot with the
// correct ext4 filesystem configuration when encryption is disabled.
func TestReserveScratchLayer_Success(t *testing.T) {
	t.Parallel()
	scsi := mocks.NewMockSCSIReserver(gomock.NewController(t))

	scratchDir := createTempDirWithFile(t, "sandbox.vhdx")
	scratchPath := filepath.Join(scratchDir, "sandbox.vhdx")

	reservationID := newGUID(t)
	expectedGuestPath := "/dev/sdb"

	scsi.EXPECT().Reserve(
		gomock.Any(),
		gomock.AssignableToTypeOf(disk.Config{}),
		scsiMount.Config{
			EnsureFilesystem: true,
			Filesystem:       "ext4",
		},
	).DoAndReturn(func(_ context.Context, diskCfg disk.Config, _ scsiMount.Config) (guid.GUID, string, error) {
		if diskCfg.HostPath == "" {
			t.Error("expected non-empty host path in disk config")
		}
		if diskCfg.ReadOnly {
			t.Error("expected ReadOnly=false for scratch")
		}
		if diskCfg.Type != disk.TypeVirtualDisk {
			t.Errorf("expected disk type %s, got %s", disk.TypeVirtualDisk, diskCfg.Type)
		}
		return reservationID, expectedGuestPath, nil
	})

	gotID, gotPath, err := reserveScratchLayer(t.Context(), scsi, "test-vm", scratchPath, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotID != reservationID {
		t.Errorf("expected reservation ID %s, got %s", reservationID, gotID)
	}
	if gotPath != expectedGuestPath {
		t.Errorf("expected guest path %q, got %q", expectedGuestPath, gotPath)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// reserveScratchLayer — encryption enabled uses xfs
// ─────────────────────────────────────────────────────────────────────────────

// TestReserveScratchLayer_EncryptionUsesXFS verifies that when scratch
// encryption is enabled, the filesystem is set to xfs and the Encrypted
// flag is propagated.
func TestReserveScratchLayer_EncryptionUsesXFS(t *testing.T) {
	t.Parallel()
	scsi := mocks.NewMockSCSIReserver(gomock.NewController(t))

	scratchDir := createTempDirWithFile(t, "sandbox.vhdx")
	scratchPath := filepath.Join(scratchDir, "sandbox.vhdx")

	reservationID := newGUID(t)

	scsi.EXPECT().Reserve(
		gomock.Any(),
		gomock.Any(),
		scsiMount.Config{
			Encrypted:        true,
			EnsureFilesystem: true,
			Filesystem:       "xfs",
		},
	).Return(reservationID, "/dev/sdb", nil)

	_, _, err := reserveScratchLayer(t.Context(), scsi, "test-vm", scratchPath, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// reserveScratchLayer — reserve failure
// ─────────────────────────────────────────────────────────────────────────────

// TestReserveScratchLayer_ReserveFailure verifies that an error from
// scsiReserver.Reserve for the scratch layer is propagated with context.
func TestReserveScratchLayer_ReserveFailure(t *testing.T) {
	t.Parallel()
	scsi := mocks.NewMockSCSIReserver(gomock.NewController(t))

	scratchDir := createTempDirWithFile(t, "sandbox.vhdx")
	scratchPath := filepath.Join(scratchDir, "sandbox.vhdx")

	scsi.EXPECT().Reserve(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(guid.GUID{}, "", errors.New("no free scsi slots"))

	_, _, err := reserveScratchLayer(t.Context(), scsi, "test-vm", scratchPath, false)
	if err == nil {
		t.Fatal("expected error from Reserve failure")
	}
	if !strings.Contains(err.Error(), "reserve scsi slot for scratch") {
		t.Errorf("expected wrapped error about reserving scsi slot, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// parseAndReserveLayers — invalid input
// ─────────────────────────────────────────────────────────────────────────────

// TestParseAndReserveLayers_InvalidInput verifies that bad input to
// layers.ParseLCOWLayers (both nil rootfs and empty layerFolders) returns
// an error without making any reservations.
func TestParseAndReserveLayers_InvalidInput(t *testing.T) {
	t.Parallel()
	scsi := mocks.NewMockSCSIReserver(gomock.NewController(t))

	// No Reserve expectations — parsing should fail before any reservation.
	plan, err := parseAndReserveLayers(t.Context(), "vm-1", "pod-1", "ctr-1", nil, nil, false, scsi)
	if err == nil {
		t.Fatal("expected error for nil rootfs and empty layer folders")
	}
	if plan != nil {
		t.Errorf("expected nil plan on parse failure, got %+v", plan)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// parseAndReserveLayers — single layer folder (insufficient)
// ─────────────────────────────────────────────────────────────────────────────

// TestParseAndReserveLayers_SingleLayerFolder verifies that providing only one
// layer folder (scratch without any parent) causes ParseLCOWLayers to fail
// with a precondition error. No reservations should be made.
func TestParseAndReserveLayers_SingleLayerFolder(t *testing.T) {
	t.Parallel()
	scsi := mocks.NewMockSCSIReserver(gomock.NewController(t))

	scratchDir := createTempDirWithFile(t, "sandbox.vhdx")
	layerFolders := []string{scratchDir}

	// No Reserve expectations — parsing should fail before any reservation.
	plan, err := parseAndReserveLayers(t.Context(), "test-vm", "pod-1", "ctr-1", layerFolders, nil, false, scsi)
	if err == nil {
		t.Fatal("expected error for single layer folder (no parent layers)")
	}
	if plan != nil {
		t.Errorf("expected nil plan on parse failure, got %+v", plan)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// parseAndReserveLayers — first RO layer reserve failure
// ─────────────────────────────────────────────────────────────────────────────

// TestParseAndReserveLayers_FirstROLayerFails verifies that when the first
// read-only layer reservation fails, the error is returned with an empty
// partial plan (no successfully reserved layers to clean up).
func TestParseAndReserveLayers_FirstROLayerFails(t *testing.T) {
	t.Parallel()
	scsi := mocks.NewMockSCSIReserver(gomock.NewController(t))

	layerDir := createTempDirWithFile(t, "layer.vhd")
	scratchDir := createTempDirWithFile(t, "sandbox.vhdx")
	layerFolders := []string{layerDir, scratchDir}

	// The single read-only layer reservation fails.
	scsi.EXPECT().Reserve(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(guid.GUID{}, "", errors.New("scsi bus full"))

	plan, err := parseAndReserveLayers(t.Context(), "vm-1", "pod-1", "ctr-1", layerFolders, nil, false, scsi)
	if err == nil {
		t.Fatal("expected error from RO layer reservation failure")
	}
	if plan == nil {
		t.Fatal("expected non-nil plan on partial failure")
	}
	if len(plan.ROLayers) != 0 {
		t.Errorf("expected 0 RO layers (none succeeded), got %d", len(plan.ROLayers))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// parseAndReserveLayers — second RO layer fails, partial result
// ─────────────────────────────────────────────────────────────────────────────

// TestParseAndReserveLayers_SecondROLayerFails verifies that when the second
// read-only layer reservation fails, the first successful reservation is still
// returned in the partial plan for cleanup.
func TestParseAndReserveLayers_SecondROLayerFails(t *testing.T) {
	t.Parallel()
	scsi := mocks.NewMockSCSIReserver(gomock.NewController(t))

	layerDir1 := createTempDirWithFile(t, "layer.vhd")
	layerDir2 := createTempDirWithFile(t, "layer.vhd")
	scratchDir := createTempDirWithFile(t, "sandbox.vhdx")

	// layerFolders: [parent1, parent2, scratch]
	layerFolders := []string{layerDir1, layerDir2, scratchDir}

	reservationID1 := newGUID(t)

	gomock.InOrder(
		// First read-only layer succeeds.
		scsi.EXPECT().Reserve(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(reservationID1, "/layer1", nil),
		// Second read-only layer fails.
		scsi.EXPECT().Reserve(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(guid.GUID{}, "", errors.New("scsi bus full")),
	)

	plan, err := parseAndReserveLayers(t.Context(), "vm-1", "pod-1", "ctr-1", layerFolders, nil, false, scsi)
	if err == nil {
		t.Fatal("expected error from second RO layer reservation failure")
	}
	// The first successfully reserved layer must be in the plan for cleanup.
	if plan == nil {
		t.Fatal("expected non-nil plan with partial results")
	}
	if len(plan.ROLayers) != 1 {
		t.Fatalf("expected 1 partial RO layer, got %d", len(plan.ROLayers))
	}
	if plan.ROLayers[0].ID != reservationID1 {
		t.Errorf("expected partial RO layer ID %s, got %s", reservationID1, plan.ROLayers[0].ID)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// parseAndReserveLayers — RO layers succeed, scratch Reserve fails
// ─────────────────────────────────────────────────────────────────────────────

// TestParseAndReserveLayers_ScratchReserveFailure verifies that when all
// read-only layers are successfully reserved but the scratch layer Reserve
// fails, the partial plan containing the RO layers is returned.
func TestParseAndReserveLayers_ScratchReserveFailure(t *testing.T) {
	t.Parallel()
	scsi := mocks.NewMockSCSIReserver(gomock.NewController(t))

	layerDir := createTempDirWithFile(t, "layer.vhd")
	scratchDir := createTempDirWithFile(t, "sandbox.vhdx")

	// layerFolders: [parent, scratch]
	layerFolders := []string{layerDir, scratchDir}

	reservationID := newGUID(t)

	gomock.InOrder(
		// Read-only layer Reserve succeeds.
		scsi.EXPECT().Reserve(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(reservationID, "/layer1", nil),
		// Scratch layer Reserve fails.
		scsi.EXPECT().Reserve(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(guid.GUID{}, "", errors.New("no free scsi slots")),
	)

	plan, err := parseAndReserveLayers(t.Context(), "test-vm", "pod-1", "ctr-1", layerFolders, nil, false, scsi)
	if err == nil {
		t.Fatal("expected error from scratch reservation failure")
	}
	// The RO layer reservation must be in the plan for cleanup.
	if plan == nil {
		t.Fatal("expected non-nil plan with partial results")
	}
	if len(plan.ROLayers) != 1 {
		t.Fatalf("expected 1 RO layer in partial plan, got %d", len(plan.ROLayers))
	}
	if plan.ROLayers[0].ID != reservationID {
		t.Errorf("expected RO layer ID %s, got %s", reservationID, plan.ROLayers[0].ID)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// parseAndReserveLayers — full success with guest path verification
// ─────────────────────────────────────────────────────────────────────────────

// TestParseAndReserveLayers_FullSuccess verifies the complete success path
// including correct guest path construction for scratch and rootfs.
func TestParseAndReserveLayers_FullSuccess(t *testing.T) {
	t.Parallel()
	scsi := mocks.NewMockSCSIReserver(gomock.NewController(t))

	layerDir := createTempDirWithFile(t, "layer.vhd")
	scratchDir := createTempDirWithFile(t, "sandbox.vhdx")
	layerFolders := []string{layerDir, scratchDir}

	roReservationID := newGUID(t)
	scratchReservationID := newGUID(t)

	gomock.InOrder(
		// Read-only layer Reserve succeeds.
		scsi.EXPECT().Reserve(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(roReservationID, "/layer1", nil),
		// Scratch Reserve succeeds.
		scsi.EXPECT().Reserve(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(scratchReservationID, "/scratch/mount", nil),
	)

	plan, err := parseAndReserveLayers(t.Context(), "test-vm", "pod-1", "ctr-1", layerFolders, nil, false, scsi)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan == nil {
		t.Fatal("expected non-nil plan")
	}

	// Verify RO layer reservation.
	if len(plan.ROLayers) != 1 {
		t.Fatalf("expected 1 RO layer, got %d", len(plan.ROLayers))
	}
	if plan.ROLayers[0].ID != roReservationID {
		t.Errorf("expected RO layer ID %s, got %s", roReservationID, plan.ROLayers[0].ID)
	}

	// Verify scratch reservation and guest path:
	// ospath.Join("linux", scratchMountPath, "scratch", podID, containerID)
	if plan.Scratch.ID != scratchReservationID {
		t.Errorf("expected scratch ID %s, got %s", scratchReservationID, plan.Scratch.ID)
	}
	expectedScratchGuestPath := "/scratch/mount/scratch/pod-1/ctr-1"
	if plan.Scratch.GuestPath != expectedScratchGuestPath {
		t.Errorf("expected scratch guest path %q, got %q", expectedScratchGuestPath, plan.Scratch.GuestPath)
	}

	// Verify rootfs guest path:
	// ospath.Join("linux", LCOWV2RootPrefixInVM, podID, containerID, RootfsPath)
	expectedRootfsPath := "/run/gcs/pods/pod-1/ctr-1/rootfs"
	if plan.RootfsGuestPath != expectedRootfsPath {
		t.Errorf("expected rootfs guest path %q, got %q", expectedRootfsPath, plan.RootfsGuestPath)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// parseAndReserveLayers — full success with multiple RO layers
// ─────────────────────────────────────────────────────────────────────────────

// TestParseAndReserveLayers_MultipleROLayers verifies that multiple read-only
// layers are reserved in order and all appear in the plan.
func TestParseAndReserveLayers_MultipleROLayers(t *testing.T) {
	t.Parallel()
	scsi := mocks.NewMockSCSIReserver(gomock.NewController(t))

	layerDir1 := createTempDirWithFile(t, "layer.vhd")
	layerDir2 := createTempDirWithFile(t, "layer.vhd")
	layerDir3 := createTempDirWithFile(t, "layer.vhd")
	scratchDir := createTempDirWithFile(t, "sandbox.vhdx")

	layerFolders := []string{layerDir1, layerDir2, layerDir3, scratchDir}

	roID1 := newGUID(t)
	roID2 := newGUID(t)
	roID3 := newGUID(t)
	scratchID := newGUID(t)

	gomock.InOrder(
		scsi.EXPECT().Reserve(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(roID1, "/layer1", nil),
		scsi.EXPECT().Reserve(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(roID2, "/layer2", nil),
		scsi.EXPECT().Reserve(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(roID3, "/layer3", nil),
		scsi.EXPECT().Reserve(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(scratchID, "/scratch", nil),
	)

	plan, err := parseAndReserveLayers(t.Context(), "test-vm", "pod-1", "ctr-1", layerFolders, nil, false, scsi)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(plan.ROLayers) != 3 {
		t.Fatalf("expected 3 RO layers, got %d", len(plan.ROLayers))
	}
	if plan.ROLayers[0].ID != roID1 || plan.ROLayers[1].ID != roID2 || plan.ROLayers[2].ID != roID3 {
		t.Errorf("RO layer IDs not in expected order: %v", plan.ROLayers)
	}
	if plan.Scratch.ID != scratchID {
		t.Errorf("expected scratch ID %s, got %s", scratchID, plan.Scratch.ID)
	}
}
