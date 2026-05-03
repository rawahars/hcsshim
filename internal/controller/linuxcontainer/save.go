//go:build windows && lcow

package linuxcontainer

import (
	"context"
	"fmt"

	"github.com/Microsoft/go-winio/pkg/guid"
	lcsave "github.com/Microsoft/hcsshim/internal/controller/linuxcontainer/save"
	"github.com/Microsoft/hcsshim/internal/controller/process"
	"github.com/Microsoft/hcsshim/internal/layers"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/logfields"

	"github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
)

// Save returns the linuxcontainer controller's migration payload as an
// [anypb.Any] tagged with [lcsave.TypeURL]. The returned envelope
// captures the container's identifiers, lifecycle stage, layer/device
// reservations, and the recursively captured (opaque) state of every
// running process inside the container.
func (c *Controller) Save(ctx context.Context) (*anypb.Any, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	state := &lcsave.Payload{
		ContainerID:         c.containerID,
		GcsContainerID:      c.gcsContainerID,
		State:               lcsave.Stage(c.state),
		IoRetryTimeout:      durationpb.New(c.ioRetryTimeout),
		ScsiReservationIds:  guidsToStrings(c.scsiResources),
		Plan9ReservationIds: guidsToStrings(c.plan9Resources),
		VpciVmbusGuids:      guidsToStrings(c.devices),
	}

	if c.layers != nil {
		ls := &lcsave.Layers{
			LayersCombined: c.layers.layersCombined,
			RootfsPath:     c.layers.rootfsPath,
			Scratch: &lcsave.LayerReservation{
				ReservationID: c.layers.scratch.id.String(),
				GuestPath:     c.layers.scratch.guestPath,
			},
		}
		if len(c.layers.roLayers) > 0 {
			ls.RoLayers = make([]*lcsave.LayerReservation, 0, len(c.layers.roLayers))
			for _, r := range c.layers.roLayers {
				ls.RoLayers = append(ls.RoLayers, &lcsave.LayerReservation{
					ReservationID: r.id.String(),
					GuestPath:     r.guestPath,
				})
			}
		}
		state.Layers = ls
	}

	if len(c.processes) > 0 {
		state.Processes = make(map[string]*anypb.Any, len(c.processes))
		for execID, p := range c.processes {
			ps, err := p.Save(ctx)
			if err != nil {
				return nil, fmt.Errorf("save process %q/%q: %w", c.containerID, execID, err)
			}
			state.Processes[execID] = ps
		}
	}

	payload, err := proto.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("marshal linuxcontainer saved state for %q: %w", c.containerID, err)
	}
	return &anypb.Any{TypeUrl: lcsave.TypeURL, Value: payload}, nil
}

func guidsToStrings(in []guid.GUID) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	for i, g := range in {
		out[i] = g.String()
	}
	return out
}

// Import rehydrates a [Controller] from a [Controller.Save]'d envelope
// without binding any VM, GCS guest, or device-controller dependencies.
// The returned controller is placed in [StateMigrating] so all operational
// APIs reject calls until [Controller.Resume] supplies the live
// dependencies and the next state. Embedded process controllers are also
// imported and must be resumed individually by the caller.
func Import(env *anypb.Any) (*Controller, error) {
	if env == nil {
		return nil, fmt.Errorf("linuxcontainer saved-state envelope is nil")
	}
	if env.GetTypeUrl() != lcsave.TypeURL {
		return nil, fmt.Errorf("unsupported linuxcontainer saved-state type %q", env.GetTypeUrl())
	}

	state := &lcsave.Payload{}
	if err := proto.Unmarshal(env.GetValue(), state); err != nil {
		return nil, fmt.Errorf("unmarshal linuxcontainer saved state: %w", err)
	}
	if v := state.GetSchemaVersion(); v != lcsave.SchemaVersion {
		return nil, fmt.Errorf("unsupported linuxcontainer saved-state schema version %d (want %d)", v, lcsave.SchemaVersion)
	}

	c := &Controller{
		containerID:    state.GetContainerID(),
		gcsContainerID: state.GetGcsContainerID(),
		state:          StateMigrating,
		ioRetryTimeout: state.GetIoRetryTimeout().AsDuration(),
		processes:      make(map[string]*process.Controller),
		terminatedCh:   make(chan struct{}),
	}

	scsiIDs, err := stringsToGuids(state.GetScsiReservationIds())
	if err != nil {
		return nil, fmt.Errorf("decode scsi reservation ids: %w", err)
	}
	c.scsiResources = scsiIDs

	plan9IDs, err := stringsToGuids(state.GetPlan9ReservationIds())
	if err != nil {
		return nil, fmt.Errorf("decode plan9 reservation ids: %w", err)
	}
	c.plan9Resources = plan9IDs

	deviceGUIDs, err := stringsToGuids(state.GetVpciVmbusGuids())
	if err != nil {
		return nil, fmt.Errorf("decode vpci vmbus guids: %w", err)
	}
	c.devices = deviceGUIDs

	if l := state.GetLayers(); l != nil {
		ls := &scsiLayers{
			layersCombined: l.GetLayersCombined(),
			rootfsPath:     l.GetRootfsPath(),
		}
		if sc := l.GetScratch(); sc != nil {
			id, err := guid.FromString(sc.GetReservationID())
			if err != nil {
				return nil, fmt.Errorf("decode scratch reservation id: %w", err)
			}
			ls.scratch = scsiReservation{id: id, guestPath: sc.GetGuestPath()}
		}
		for _, ro := range l.GetRoLayers() {
			id, err := guid.FromString(ro.GetReservationID())
			if err != nil {
				return nil, fmt.Errorf("decode ro layer reservation id: %w", err)
			}
			ls.roLayers = append(ls.roLayers, scsiReservation{id: id, guestPath: ro.GetGuestPath()})
		}
		c.layers = ls
	}

	for execID, ps := range state.GetProcesses() {
		p, err := process.Import(ps, c.containerID)
		if err != nil {
			return nil, fmt.Errorf("import process %q/%q: %w", c.containerID, execID, err)
		}
		c.processes[execID] = p
	}

	return c, nil
}

// Resume binds the live VM identifier, GCS pod identifier, and host/guest
// dependencies to a controller previously produced by [Import] and
// transitions it from [StateMigrating] into next. Embedded process
// controllers are not resumed here; the caller is responsible for invoking
// [process.Controller.Resume] on each entry returned by
// [Controller.ListProcesses].
func (c *Controller) Resume(
	next State,
	vmID string,
	gcsPodID string,
	guestMgr guest,
	scsiCtrl scsiController,
	plan9Ctrl plan9Controller,
	vpci vPCIController,
) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.vmID = vmID
	c.gcsPodID = gcsPodID
	c.guest = guestMgr
	c.scsi = scsiCtrl
	c.plan9 = plan9Ctrl
	c.vpci = vpci
	c.state = next
}

func stringsToGuids(in []string) ([]guid.GUID, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]guid.GUID, 0, len(in))
	for _, s := range in {
		g, err := guid.FromString(s)
		if err != nil {
			return nil, fmt.Errorf("parse guid %q: %w", s, err)
		}
		out = append(out, g)
	}
	return out, nil
}

// ContainerID returns the host/shim container identifier for this controller.
func (c *Controller) ContainerID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.containerID
}

func (c *Controller) Patch(ctx context.Context, request *task.CreateTaskRequest) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.layers != nil {
		lcowLayers, err := layers.ParseLCOWLayers(request.Rootfs, nil)
		if err != nil {
			return fmt.Errorf("parse destination lcow layers: %w", err)
		}
		if got, want := len(lcowLayers.Layers), len(c.layers.roLayers); got != want {
			return fmt.Errorf("ro layer count mismatch: got %d, want %d", got, want)
		}
		for i, ro := range c.layers.roLayers {
			if err := c.scsi.UpdateDiskHostPath(ro.id, lcowLayers.Layers[i].VHDPath); err != nil {
				return fmt.Errorf("patch ro layer %d: %w", i, err)
			}
		}
		if err := c.scsi.UpdateDiskHostPath(c.layers.scratch.id, lcowLayers.ScratchVHDPath); err != nil {
			return fmt.Errorf("patch scratch layer: %w", err)
		}
	}

	log.G(ctx).WithFields(logrus.Fields{
		logfields.ContainerID: request.ID,
	}).Debug("patched container resource paths")

	c.containerID = request.ID
	return nil
}
