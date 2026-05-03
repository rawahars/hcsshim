//go:build windows && lcow

package migration

import (
	"context"
	"fmt"

	save "github.com/Microsoft/hcsshim/internal/controller/migration/save"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/logfields"

	"github.com/containerd/errdefs"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// PrepareSource arms the controller as the source of a live migration session.
// On success the controller transitions to [StateSourcePrepared] and is ready
// for a subsequent [Controller.ExportState] call. A repeat call for the same
// session is a no-op.
func (c *Controller) PrepareSource(ctx context.Context, opts *PrepareSourceOptions) error {
	if opts == nil {
		return fmt.Errorf("options are required: %w", errdefs.ErrInvalidArgument)
	}
	if opts.SessionID == "" {
		return fmt.Errorf("session id is required: %w", errdefs.ErrInvalidArgument)
	}
	if opts.VMController == nil {
		return fmt.Errorf("vm controller is required: %w", errdefs.ErrInvalidArgument)
	}
	if opts.PodControllers == nil {
		return fmt.Errorf("pod controllers map is required: %w", errdefs.ErrInvalidArgument)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != StateIdle {
		// If we already called this API, then this is a no-op.
		if c.state == StateSourcePrepared && c.sessionID == opts.SessionID {
			return nil
		}
		return fmt.Errorf("controller is in state %s for session %q: %w", c.state, c.sessionID, errdefs.ErrAlreadyExists)
	}

	migrationOpts := opts.MigrationOpts
	if migrationOpts == nil {
		migrationOpts = &hcsschema.MigrationInitializeOptions{}
	}
	migrationOpts.Origin = opts.Origin

	if err := opts.VMController.InitializeLiveMigrationOnSource(ctx, migrationOpts); err != nil {
		return fmt.Errorf("initialize live migration on source vm: %w", err)
	}

	c.sessionID = opts.SessionID
	c.origin = opts.Origin
	c.vmController = opts.VMController
	c.podControllers = opts.PodControllers
	c.state = StateSourcePrepared

	log.G(ctx).WithField(logfields.SessionID, c.sessionID).Info("migration source prepared")
	return nil
}

// ExportState produces the opaque, versioned sandbox-level [anypb.Any]
// envelope that the destination shim consumes via [Controller.ImportState].
// It is only valid after a successful [Controller.PrepareSource] and
// transitions the controller to [StateExported]. The VM and per-pod
// payloads are themselves opaque [anypb.Any] envelopes owned by the
// respective controllers; the top-level envelope merely carries them.
func (c *Controller) ExportState(ctx context.Context) (*anypb.Any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != StateSourcePrepared && c.state != StateExported {
		return nil, fmt.Errorf("export requires state %s or %s (current: %s): %w", StateSourcePrepared, StateExported, c.state, errdefs.ErrFailedPrecondition)
	}

	// Save the VM state.
	vmAny, err := c.vmController.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("save vm controller: %w", err)
	}

	// Save all the pod controller states as opaque envelopes.
	pods := make([]*anypb.Any, 0, len(c.podControllers))
	for podID, podCtrl := range c.podControllers {
		ps, err := podCtrl.Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("save pod %q: %w", podID, err)
		}
		pods = append(pods, ps)
	}

	payload, err := proto.Marshal(&save.Payload{
		SchemaVersion: save.SchemaVersion,
		Vm:            vmAny,
		Pods:          pods,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal sandbox saved state: %w", err)
	}

	c.state = StateExported
	log.G(ctx).WithField(logfields.SessionID, c.sessionID).Info("migration source state exported")

	return &anypb.Any{TypeUrl: save.TypeURL, Value: payload}, nil
}
