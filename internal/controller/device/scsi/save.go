//go:build windows && (lcow || wcow)

package scsi

import (
	"context"
	"fmt"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Microsoft/hcsshim/internal/controller/device/scsi/disk"
	scsisave "github.com/Microsoft/hcsshim/internal/controller/device/scsi/save"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// Save returns the SCSI sub-controller's migration payload as an
// [anypb.Any] tagged with [scsisave.TypeURL]. The returned envelope
// captures the controller topology, every attached disk keyed by absolute
// slot, and the outstanding partition reservations that pin disks against
// eviction.
func (c *Controller) Save(_ context.Context) (*anypb.Any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	state := &scsisave.Payload{
		NumControllers: uint32(len(c.controllerSlots) / numLUNsPerController),
		Disks:          make(map[uint32]*scsisave.DiskState, len(c.disksByPath)),
		Reservations:   make(map[string]*scsisave.Reservation, len(c.reservations)),
	}

	for slot, d := range c.controllerSlots {
		if d == nil {
			continue
		}
		state.Disks[uint32(slot)] = d.Save()
	}

	for id, r := range c.reservations {
		state.Reservations[id.String()] = &scsisave.Reservation{
			Slot:      uint32(r.controllerSlot),
			Partition: r.partition,
		}
	}

	payload, err := proto.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("marshal scsi saved state: %w", err)
	}
	return &anypb.Any{TypeUrl: scsisave.TypeURL, Value: payload}, nil
}

// Import rehydrates a [Controller] from a [Controller.Save]'d envelope
// without binding any host/guest interfaces. The returned controller is
// inert until [Controller.Resume] supplies the live interfaces. A nil
// envelope produces an empty controller with the default topology.
func Import(env *anypb.Any) (*Controller, error) {
	state := &scsisave.Payload{}
	if env != nil {
		if env.GetTypeUrl() != scsisave.TypeURL {
			return nil, fmt.Errorf("unsupported scsi saved-state type %q", env.GetTypeUrl())
		}
		if err := proto.Unmarshal(env.GetValue(), state); err != nil {
			return nil, fmt.Errorf("unmarshal scsi saved state: %w", err)
		}
		if v := state.GetSchemaVersion(); v != scsisave.SchemaVersion {
			return nil, fmt.Errorf("unsupported scsi saved-state schema version %d (want %d)", v, scsisave.SchemaVersion)
		}
	}

	numCtrls := int(state.GetNumControllers())
	c := &Controller{
		reservations:    make(map[guid.GUID]*reservation, len(state.GetReservations())),
		disksByPath:     make(map[string]int, len(state.GetDisks())),
		controllerSlots: make([]*disk.Disk, numCtrls*numLUNsPerController),
		isMigrating:     true,
	}

	for slot, ds := range state.GetDisks() {
		idx := int(slot)
		if idx >= len(c.controllerSlots) {
			continue
		}
		controller, lun := uint(idx/numLUNsPerController), uint(idx%numLUNsPerController)
		d := disk.Import(ds, controller, lun)
		if d == nil {
			continue
		}
		c.controllerSlots[idx] = d
		if hp := ds.GetConfig().GetHostPath(); hp != "" {
			c.disksByPath[hp] = idx
		}
	}

	for idStr, r := range state.GetReservations() {
		id, err := guid.FromString(idStr)
		if err != nil {
			continue
		}
		c.reservations[id] = &reservation{
			controllerSlot: int(r.GetSlot()),
			partition:      r.GetPartition(),
		}
	}
	return c, nil
}

// UpdateDiskHostPath rewrites the host-side path of the disk backing the
// given reservation. Only valid while the controller is in the migration
// window (post-Import, pre-Resume); it exists so destination-side VHD
// locations can be patched into place before the VM resumes.
func (c *Controller) UpdateDiskHostPath(reservationID guid.GUID, newPath string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isMigrating {
		return fmt.Errorf("UpdateDiskHostPath only valid while migrating")
	}

	// Find the reservation.
	r, ok := c.reservations[reservationID]
	if !ok {
		return fmt.Errorf("reservation %s not found", reservationID)
	}

	// Find the requested disk.
	d := c.controllerSlots[r.controllerSlot]
	if d == nil {
		return fmt.Errorf("disk for reservation %s not found", reservationID)
	}

	// Update old path to new path.
	oldPath := d.HostPath()
	if oldPath == newPath {
		return nil
	}
	if slot, ok := c.disksByPath[oldPath]; ok && slot == r.controllerSlot {
		delete(c.disksByPath, oldPath)
	}
	d.UpdateHostPath(newPath)
	c.disksByPath[newPath] = r.controllerSlot
	return nil
}

// Resume binds the live host/guest interfaces to a controller previously
// produced by [Import]. Must be called once the destination VM is running
// before any reservation, attach, or mount APIs are invoked.
func (c *Controller) Resume(vm VMSCSIOps, guest GuestSCSIOps) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.vm = vm
	c.guest = guest
	c.isMigrating = false
}
