//go:build windows && lcow

package lcow

import (
	"errors"
	"testing"

	"github.com/Microsoft/go-winio/pkg/guid"
	"go.uber.org/mock/gomock"

	"github.com/Microsoft/hcsshim/internal/builder/container/mocks"
	"github.com/Microsoft/hcsshim/internal/controller/device/vpci"
	"github.com/opencontainers/runtime-spec/specs-go"
)

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

// newGUID generates a random GUID and fails the test on error.
func newGUID(t *testing.T) guid.GUID {
	t.Helper()
	id, err := guid.NewV4()
	if err != nil {
		t.Fatalf("failed to generate GUID: %v", err)
	}
	return id
}

// ─────────────────────────────────────────────────────────────────────────────
// reserveAndUpdateDevices — empty device list
// ─────────────────────────────────────────────────────────────────────────────

// TestReserveDevices_EmptyList verifies that an empty device slice produces
// no reservations and no error.
func TestReserveDevices_EmptyList(t *testing.T) {
	t.Parallel()
	vpciReserver := mocks.NewMockVPCIReserver(gomock.NewController(t))

	reservations, err := reserveAndUpdateDevices(t.Context(), vpciReserver, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(reservations) != 0 {
		t.Errorf("expected 0 reservations, got %d", len(reservations))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// reserveAndUpdateDevices — single valid device
// ─────────────────────────────────────────────────────────────────────────────

// TestReserveDevices_SingleDevice verifies that a single valid device is
// reserved and its spec ID is rewritten to the VMBus GUID.
func TestReserveDevices_SingleDevice(t *testing.T) {
	t.Parallel()
	vpciReserver := mocks.NewMockVPCIReserver(gomock.NewController(t))

	vmBusGUID := newGUID(t)
	devicePath := `PCI\VEN_1234&DEV_5678`

	vpciReserver.EXPECT().Reserve(gomock.Any(), vpci.Device{
		DeviceInstanceID:     devicePath,
		VirtualFunctionIndex: 0,
	}).Return(vmBusGUID, nil)

	specDevs := []specs.WindowsDevice{
		{ID: devicePath, IDType: vpci.DeviceIDType},
	}

	reservations, err := reserveAndUpdateDevices(t.Context(), vpciReserver, specDevs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(reservations) != 1 {
		t.Fatalf("expected 1 reservation, got %d", len(reservations))
	}
	if reservations[0] != vmBusGUID {
		t.Errorf("expected reservation GUID %s, got %s", vmBusGUID, reservations[0])
	}
	if specDevs[0].ID != vmBusGUID.String() {
		t.Errorf("expected spec device ID rewritten to %s, got %s", vmBusGUID, specDevs[0].ID)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// reserveAndUpdateDevices — device with virtual function index
// ─────────────────────────────────────────────────────────────────────────────

// TestReserveDevices_WithVirtualFunctionIndex verifies that a device path
// containing a trailing VF index (e.g. "DEVICE_ID/2") is parsed into the
// correct DeviceInstanceID and VirtualFunctionIndex.
func TestReserveDevices_WithVirtualFunctionIndex(t *testing.T) {
	t.Parallel()
	vpciReserver := mocks.NewMockVPCIReserver(gomock.NewController(t))

	vmBusGUID := newGUID(t)
	devicePath := `PCI\VEN_1234&DEV_5678`

	vpciReserver.EXPECT().Reserve(gomock.Any(), vpci.Device{
		DeviceInstanceID:     devicePath,
		VirtualFunctionIndex: 3,
	}).Return(vmBusGUID, nil)

	specDevs := []specs.WindowsDevice{
		{ID: devicePath + `/3`, IDType: vpci.DeviceIDType},
	}

	reservations, err := reserveAndUpdateDevices(t.Context(), vpciReserver, specDevs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(reservations) != 1 {
		t.Fatalf("expected 1 reservation, got %d", len(reservations))
	}
	if specDevs[0].ID != vmBusGUID.String() {
		t.Errorf("expected spec device ID rewritten to %s, got %s", vmBusGUID, specDevs[0].ID)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// reserveAndUpdateDevices — multiple devices in order
// ─────────────────────────────────────────────────────────────────────────────

// TestReserveDevices_MultipleDevices verifies that multiple devices are
// reserved in order and all spec IDs are rewritten.
func TestReserveDevices_MultipleDevices(t *testing.T) {
	t.Parallel()
	vpciReserver := mocks.NewMockVPCIReserver(gomock.NewController(t))

	guid1, guid2 := newGUID(t), newGUID(t)
	path1, path2 := `PCI\DEV_A`, `PCI\DEV_B`

	gomock.InOrder(
		vpciReserver.EXPECT().Reserve(gomock.Any(), vpci.Device{
			DeviceInstanceID: path1,
		}).Return(guid1, nil),
		vpciReserver.EXPECT().Reserve(gomock.Any(), vpci.Device{
			DeviceInstanceID: path2,
		}).Return(guid2, nil),
	)

	specDevs := []specs.WindowsDevice{
		{ID: path1, IDType: vpci.DeviceIDTypeLegacy},
		{ID: path2, IDType: vpci.GpuDeviceIDType},
	}

	reservations, err := reserveAndUpdateDevices(t.Context(), vpciReserver, specDevs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(reservations) != 2 {
		t.Fatalf("expected 2 reservations, got %d", len(reservations))
	}
	if reservations[0] != guid1 || reservations[1] != guid2 {
		t.Errorf("unexpected reservation GUIDs: %v", reservations)
	}
	if specDevs[0].ID != guid1.String() || specDevs[1].ID != guid2.String() {
		t.Errorf("spec device IDs not rewritten: %q, %q", specDevs[0].ID, specDevs[1].ID)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// reserveAndUpdateDevices — unsupported device type
// ─────────────────────────────────────────────────────────────────────────────

// TestReserveDevices_UnsupportedType verifies that an unsupported device type
// returns an error without calling Reserve.
func TestReserveDevices_UnsupportedType(t *testing.T) {
	t.Parallel()
	vpciReserver := mocks.NewMockVPCIReserver(gomock.NewController(t))

	// No Reserve expectations — Reserve must not be called.
	specDevs := []specs.WindowsDevice{
		{ID: `PCI\DEV_X`, IDType: "unsupported-type"},
	}

	_, err := reserveAndUpdateDevices(t.Context(), vpciReserver, specDevs)
	if err == nil {
		t.Fatal("expected error for unsupported device type")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// reserveAndUpdateDevices — reserve failure returns partial results
// ─────────────────────────────────────────────────────────────────────────────

// TestReserveDevices_ReserveFailure verifies that when Reserve fails on the
// second device, the first reservation is still returned for cleanup.
func TestReserveDevices_ReserveFailure(t *testing.T) {
	t.Parallel()
	vpciReserver := mocks.NewMockVPCIReserver(gomock.NewController(t))

	guid1 := newGUID(t)
	path1, path2 := `PCI\DEV_A`, `PCI\DEV_B`

	gomock.InOrder(
		vpciReserver.EXPECT().Reserve(gomock.Any(), vpci.Device{
			DeviceInstanceID: path1,
		}).Return(guid1, nil),
		vpciReserver.EXPECT().Reserve(gomock.Any(), vpci.Device{
			DeviceInstanceID: path2,
		}).Return(guid.GUID{}, errors.New("reservation failed")),
	)

	specDevs := []specs.WindowsDevice{
		{ID: path1, IDType: vpci.DeviceIDType},
		{ID: path2, IDType: vpci.DeviceIDType},
	}

	reservations, err := reserveAndUpdateDevices(t.Context(), vpciReserver, specDevs)
	if err == nil {
		t.Fatal("expected error from Reserve failure")
	}
	// The first successful reservation must still be returned.
	if len(reservations) != 1 {
		t.Fatalf("expected 1 partial reservation, got %d", len(reservations))
	}
	if reservations[0] != guid1 {
		t.Errorf("expected partial reservation GUID %s, got %s", guid1, reservations[0])
	}
	if specDevs[0].ID != guid1.String() {
		t.Errorf("expected first device ID rewritten to %s, got %s", guid1, specDevs[0].ID)
	}
	if specDevs[1].ID != path2 {
		t.Errorf("expected failing device ID to remain %s, got %s", path2, specDevs[1].ID)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// reserveAndUpdateDevices — unsupported type after valid device
// ─────────────────────────────────────────────────────────────────────────────

// TestReserveDevices_UnsupportedTypeAfterValid verifies that an unsupported
// type on the second device returns the first successful reservation.
func TestReserveDevices_UnsupportedTypeAfterValid(t *testing.T) {
	t.Parallel()
	vpciReserver := mocks.NewMockVPCIReserver(gomock.NewController(t))

	guid1 := newGUID(t)

	vpciReserver.EXPECT().Reserve(gomock.Any(), vpci.Device{
		DeviceInstanceID: `PCI\DEV_A`,
	}).Return(guid1, nil)

	specDevs := []specs.WindowsDevice{
		{ID: `PCI\DEV_A`, IDType: vpci.DeviceIDType},
		{ID: `PCI\DEV_B`, IDType: "bad-type"},
	}

	reservations, err := reserveAndUpdateDevices(t.Context(), vpciReserver, specDevs)
	if err == nil {
		t.Fatal("expected error for unsupported device type")
	}
	if len(reservations) != 1 {
		t.Fatalf("expected 1 partial reservation, got %d", len(reservations))
	}
	if specDevs[0].ID != guid1.String() {
		t.Errorf("expected first device ID rewritten to %s, got %s", guid1, specDevs[0].ID)
	}
	if specDevs[1].ID != `PCI\DEV_B` {
		t.Errorf("expected unsupported device ID to remain %s, got %s", `PCI\DEV_B`, specDevs[1].ID)
	}
}
