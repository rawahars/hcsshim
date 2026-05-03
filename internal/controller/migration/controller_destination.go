//go:build windows && lcow

package migration

import (
	"context"
	"fmt"

	save "github.com/Microsoft/hcsshim/internal/controller/migration/save"
	"github.com/Microsoft/hcsshim/internal/controller/pod"
	"github.com/Microsoft/hcsshim/internal/controller/vm"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/logfields"
	"github.com/Microsoft/hcsshim/internal/oci"
	hcsannotations "github.com/Microsoft/hcsshim/pkg/annotations"

	"github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/containerd/errdefs"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

func (c *Controller) ImportState(ctx context.Context, opts *ImportStateOptions) error {
	if opts == nil {
		return fmt.Errorf("options are required: %w", errdefs.ErrInvalidArgument)
	}
	if opts.SessionID == "" {
		return fmt.Errorf("session id is required: %w", errdefs.ErrInvalidArgument)
	}
	if opts.VMController == nil {
		return fmt.Errorf("vm controller is required: %w", errdefs.ErrInvalidArgument)
	}
	if opts.SandboxID == "" {
		return fmt.Errorf("sandbox id is required: %w", errdefs.ErrInvalidArgument)
	}
	if opts.PodControllers == nil {
		return fmt.Errorf("pod controllers map is required: %w", errdefs.ErrInvalidArgument)
	}
	if opts.Checkpoint == nil {
		return fmt.Errorf("sandbox saved state is required: %w", errdefs.ErrInvalidArgument)
	}
	if opts.Checkpoint.TypeUrl != save.TypeURL {
		return fmt.Errorf("unsupported sandbox saved-state type %q: %w", opts.Checkpoint.TypeUrl, errdefs.ErrInvalidArgument)
	}

	decoded := &save.Payload{}
	if err := proto.Unmarshal(opts.Checkpoint.Value, decoded); err != nil {
		return fmt.Errorf("unmarshal sandbox saved state: %w", err)
	}
	if decoded.GetSchemaVersion() != save.SchemaVersion {
		return fmt.Errorf("sandbox saved-state schema version %d not supported (want %d): %w", decoded.GetSchemaVersion(), save.SchemaVersion, errdefs.ErrInvalidArgument)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != StateIdle {
		if c.state == StateImported && c.sessionID == opts.SessionID {
			return nil
		}

		return fmt.Errorf("controller is in state %s for session %q: %w", c.state, c.sessionID, errdefs.ErrAlreadyExists)
	}

	if err := opts.VMController.Import(decoded.GetVm()); err != nil {
		return fmt.Errorf("import vm controller: %w", err)
	}

	pending := 0
	for _, podAny := range decoded.GetPods() {
		p, err := pod.Import(podAny)
		if err != nil {
			return fmt.Errorf("import pod: %w", err)
		}
		opts.PodControllers[p.PodID()] = p
		pending += len(p.ListContainers())
	}

	c.sessionID = opts.SessionID
	c.sandboxID = opts.SandboxID
	c.origin = opts.Origin
	c.vmController = opts.VMController
	c.podControllers = opts.PodControllers
	c.pendingPatches = pending
	c.state = StateImported

	log.G(ctx).WithField(logfields.SessionID, c.sessionID).Info("migration destination state imported")
	return nil
}

func (c *Controller) PrepareDestination(ctx context.Context, sessionID string, migrationOpts *hcsschema.MigrationInitializeOptions) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != StateImported {
		return fmt.Errorf("prepare destination not valid in state %s: %w", c.state, errdefs.ErrFailedPrecondition)
	}

	// Default options and stamp the destination origin so HCS sees a
	// complete config regardless of caller input.
	if migrationOpts == nil {
		migrationOpts = &hcsschema.MigrationInitializeOptions{}
	}
	migrationOpts.Origin = c.origin

	if err := c.vmController.CreateVM(ctx, &vm.CreateOptions{
		ID:               fmt.Sprintf("%s@vm", c.sandboxID),
		MigrationOptions: migrationOpts,
	}); err != nil {
		return fmt.Errorf("create destination vm: %w", err)
	}

	c.state = StateDestinationPrepared
	log.G(ctx).WithField(logfields.SessionID, sessionID).Info("migration destination prepared")
	return nil
}

func (c *Controller) PatchResourcePaths(
	ctx context.Context,
	request *task.CreateTaskRequest,
	annotations map[string]string,
) error {
	if request == nil {
		return fmt.Errorf("request is required: %w", errdefs.ErrInvalidArgument)
	}
	if request.ID == "" {
		return fmt.Errorf("destination container id is required: %w", errdefs.ErrInvalidArgument)
	}
	sourceContainerID, ok := annotations[hcsannotations.LiveMigrationSourceContainerID]
	if !ok {
		return fmt.Errorf("annotation %q is required: %w", hcsannotations.LiveMigrationSourceContainerID, errdefs.ErrInvalidArgument)
	}
	isSandbox := annotations[hcsannotations.KubernetesContainerType] == string(oci.KubernetesContainerTypeSandbox)

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != StateImported {
		return fmt.Errorf("patch not valid in state %s: %w", c.state, errdefs.ErrFailedPrecondition)
	}

	// Locate the source container's owning pod.
	var (
		sourcePodID string
		podCtrl     *pod.Controller
	)
	for pid, p := range c.podControllers {
		if _, err := p.GetContainer(sourceContainerID); err == nil {
			sourcePodID = pid
			podCtrl = p
			break
		}
	}
	if podCtrl == nil {
		return fmt.Errorf("source container %q not found: %w", sourceContainerID, errdefs.ErrNotFound)
	}
	if isSandbox && sourceContainerID != sourcePodID {
		return fmt.Errorf("sandbox container id %q does not match source pod id %q", sourceContainerID, sourcePodID)
	}

	if err := podCtrl.Patch(ctx, sourceContainerID, request, isSandbox); err != nil {
		return fmt.Errorf("patch pod %q: %w", sourcePodID, err)
	}

	if isSandbox && sourcePodID != request.ID {
		delete(c.podControllers, sourcePodID)
		c.podControllers[request.ID] = podCtrl
	}

	if c.pendingPatches > 0 {
		c.pendingPatches--
	}

	log.G(ctx).WithFields(logrus.Fields{
		logfields.SessionID:   c.sessionID,
		logfields.ContainerID: request.ID,
	}).Info("migration container resource paths patched")
	return nil
}
