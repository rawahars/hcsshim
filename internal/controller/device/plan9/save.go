//go:build windows && lcow

package plan9

import (
	"context"
	"fmt"

	"github.com/Microsoft/go-winio/pkg/guid"
	plan9save "github.com/Microsoft/hcsshim/internal/controller/device/plan9/save"
	"github.com/Microsoft/hcsshim/internal/controller/device/plan9/share"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// Save returns the Plan9 sub-controller's migration payload as an
// [anypb.Any] tagged with [plan9save.TypeURL]. The returned envelope
// captures the LCOW file shares keyed by host path together with their
// outstanding reservations so the destination can re-establish in-guest
// mounts on resume.
func (c *Controller) Save(_ context.Context) (*anypb.Any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	state := &plan9save.Payload{
		SchemaVersion:        plan9save.SchemaVersion,
		NoWritableFileShares: c.noWritableFileShares,
		NameCounter:          c.nameCounter,
		Shares:               make(map[string]*plan9save.ShareState, len(c.sharesByHostPath)),
		Reservations:         make(map[string]string, len(c.reservations)),
	}
	for hp, sh := range c.sharesByHostPath {
		state.Shares[hp] = sh.Save()
	}
	for id, r := range c.reservations {
		state.Reservations[id.String()] = r.hostPath
	}

	payload, err := proto.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("marshal plan9 saved state: %w", err)
	}
	return &anypb.Any{TypeUrl: plan9save.TypeURL, Value: payload}, nil
}

// Import rehydrates a [Controller] from a [Controller.Save]'d envelope
// without binding any host/guest interfaces. The returned controller is
// inert until [Controller.Resume] supplies the live interfaces.
func Import(env *anypb.Any) (*Controller, error) {
	state := &plan9save.Payload{}
	if env != nil {
		if env.GetTypeUrl() != plan9save.TypeURL {
			return nil, fmt.Errorf("unsupported plan9 saved-state type %q", env.GetTypeUrl())
		}
		if err := proto.Unmarshal(env.GetValue(), state); err != nil {
			return nil, fmt.Errorf("unmarshal plan9 saved state: %w", err)
		}
		if v := state.GetSchemaVersion(); v != plan9save.SchemaVersion {
			return nil, fmt.Errorf("unsupported plan9 saved-state schema version %d (want %d)", v, plan9save.SchemaVersion)
		}
	}

	c := &Controller{
		reservations:     make(map[guid.GUID]*reservation),
		sharesByHostPath: make(map[string]*share.Share),
		isMigrating:      true,
	}

	c.noWritableFileShares = state.GetNoWritableFileShares()
	c.nameCounter = state.GetNameCounter()

	// Pass 1: rebuild shares so we can resolve names in pass 2.
	for hp, ss := range state.GetShares() {
		sh := share.Import(ss, hp)
		if sh == nil {
			continue
		}
		c.sharesByHostPath[hp] = sh
	}

	// Pass 2: rebuild reservations, looking up each share's name.
	for idStr, hp := range state.GetReservations() {
		id, err := guid.FromString(idStr)
		if err != nil {
			continue
		}
		var name string
		if sh, ok := c.sharesByHostPath[hp]; ok {
			name = sh.Name()
		}
		c.reservations[id] = &reservation{hostPath: hp, name: name}
	}
	return c, nil
}

// Resume binds the live host/guest interfaces to a controller previously
// produced by [Import]. Must be called once the destination VM is running
// before any reservation or mount APIs are invoked.
func (c *Controller) Resume(vm vmPlan9, guest guestPlan9) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.vmPlan9 = vm
	c.guest = guest
	c.isMigrating = false
}
