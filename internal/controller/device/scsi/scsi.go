//go:build windows

package scsi

import (
	"sync"
)

// Manager implements the methods to manage the full SCSI disk lifecycle —
// slot allocation, VM attach, guest mount, and teardown — across one or more
// controllers on a Hyper-V VM. All operations are serialized by a single mutex.
type Manager struct {
	// mu serializes all public operations on the Manager.
	mu sync.Mutex

	// vmID identifies the HCS compute system. Immutable after construction.
	vmID string

	// numControllers is the number of SCSI controllers on the VM. Immutable after construction.
	numControllers int

	// attachmentMap tracks SCSI slot occupancy keyed by controller and LUN. Guarded by mu.
	attachmentMap map[VMSlot]*attachment

	// mappingMap indexes active mappings by caller-supplied ID. Guarded by mu.
	mappingMap map[string]*mapping

	// nextMountIdx is a monotonic counter for generating unique guest mount paths. Guarded by mu.
	nextMountIdx int

	// vmSCSI is the host-side interface for adding and removing disks from the VM. Immutable after construction.
	vmSCSI vmSCSI

	// linuxGuestSCSI is the guest-side interface for SCSI operations in LCOW guests. Immutable after construction.
	linuxGuestSCSI linuxGuestSCSI

	// windowsGuestSCSI is the guest-side interface for SCSI operations in WCOW guests. Immutable after construction.
	windowsGuestSCSI windowsGuestSCSI
}

// New creates a new [Manager] for the given VM and controllers.
func New(
	vmID string,
	vmScsi vmSCSI,
	linuxGuestScsi linuxGuestSCSI,
	windowsGuestScsi windowsGuestSCSI,
	numControllers int,
	reservedSlots []VMSlot,
) *Manager {
	m := &Manager{
		vmID:             vmID,
		numControllers:   numControllers,
		attachmentMap:    make(map[VMSlot]*attachment),
		mappingMap:       make(map[string]*mapping),
		vmSCSI:           vmScsi,
		linuxGuestSCSI:   linuxGuestScsi,
		windowsGuestSCSI: windowsGuestScsi,
	}

	// Pre-populate attachmentMap with reserved slots so they are never allocated.
	for _, s := range reservedSlots {
		m.attachmentMap[s] = &attachment{
			controller: s.Controller,
			lun:        s.LUN,
			state:      attachReserved,
			partitions: make(map[uint64]*mount),
		}
	}

	return m
}
