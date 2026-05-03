//go:build windows && lcow

package service

import (
	"context"
	"fmt"
	"time"

	migrationcontroller "github.com/Microsoft/hcsshim/internal/controller/migration"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/logfields"
	"github.com/Microsoft/hcsshim/internal/oci"
	"github.com/Microsoft/hcsshim/pkg/annotations"
	"github.com/Microsoft/hcsshim/pkg/migration"

	eventstypes "github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/api/runtime/task/v2"
)

// prepareAndExportSandboxInternal delegates to the migration controller to
// quiesce the source sandbox and produce the opaque snapshot consumed by the
// destination's ImportSandbox call.
func (s *Service) prepareAndExportSandboxInternal(ctx context.Context, request *migration.PrepareAndExportSandboxRequest) (*migration.PrepareAndExportSandboxResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.migrationController.PrepareSource(ctx, &migrationcontroller.PrepareSourceOptions{
		InitOptions: migrationcontroller.InitOptions{
			SessionID:      request.SessionID,
			Origin:         hcsschema.MigrationOriginSource,
			VMController:   s.vmController,
			PodControllers: s.podControllers,
		},
		MigrationOpts: migration.InitializeOptionsFromProto(request.InitOptions),
	}); err != nil {
		return nil, fmt.Errorf("prepare migration source: %w", err)
	}

	cfg, err := s.migrationController.ExportState(ctx)
	if err != nil {
		return nil, fmt.Errorf("export migration source state: %w", err)
	}
	return &migration.PrepareAndExportSandboxResponse{Config: cfg}, nil
}

// importSandboxInternal delegates to the migration controller to rehydrate
// the destination shim from the source's opaque snapshot. The Service-owned
// vm controller and pod controllers map are mutated in place.
func (s *Service) importSandboxInternal(ctx context.Context, request *migration.ImportSandboxRequest) (*migration.ImportSandboxResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.migrationController.ImportState(ctx, &migrationcontroller.ImportStateOptions{
		InitOptions: migrationcontroller.InitOptions{
			SessionID:      request.SessionID,
			Origin:         hcsschema.MigrationOriginDestination,
			VMController:   s.vmController,
			PodControllers: s.podControllers,
		},
		SandboxID:  request.SandboxID,
		Checkpoint: request.Config,
	}); err != nil {
		return nil, fmt.Errorf("import migration destination state: %w", err)
	}

	s.sandboxID = request.SandboxID
	for podID, podCtrl := range s.podControllers {
		for containerID := range podCtrl.ListContainers() {
			s.containerPodMapping[containerID] = podID
		}
	}
	return &migration.ImportSandboxResponse{}, nil
}

// prepareSandboxInternal delegates to the migration controller to create the
// destination-side HCS compute system from the rehydrated, NewTask-patched
// sandbox state.
func (s *Service) prepareSandboxInternal(ctx context.Context, request *migration.PrepareSandboxRequest) (*migration.PrepareSandboxResponse, error) {
	if err := s.migrationController.PrepareDestination(
		ctx,
		request.SessionID,
		migration.InitializeOptionsFromProto(request.InitOptions),
	); err != nil {
		return nil, fmt.Errorf("prepare migration destination: %w", err)
	}
	return &migration.PrepareSandboxResponse{}, nil
}

// transferSandboxInternal delegates to the migration controller to drive the
// memory transfer between source and destination over the duplicated socket.
func (s *Service) transferSandboxInternal(ctx context.Context, request *migration.TransferSandboxRequest) (*migration.TransferSandboxResponse, error) {
	var timeout time.Duration
	if request.Timeout != nil {
		timeout = request.Timeout.AsDuration()
	}
	if err := s.migrationController.Transfer(ctx, request.SessionID, timeout); err != nil {
		return nil, err
	}
	return &migration.TransferSandboxResponse{}, nil
}

// finalizeSandboxInternal delegates to the migration controller to terminate
// the session per the requested action.
func (s *Service) finalizeSandboxInternal(ctx context.Context, request *migration.FinalizeSandboxRequest) (*migration.FinalizeSandboxResponse, error) {
	if err := s.migrationController.Finalize(ctx, request.SessionID, request.Action); err != nil {
		return nil, err
	}
	return &migration.FinalizeSandboxResponse{}, nil
}

// notificationsInternal subscribes the calling stream to the migration
// controller's notification fanout and forwards every notification until the
// session terminates or the client disconnects.
func (s *Service) notificationsInternal(ctx context.Context, request *migration.NotificationsRequest, server migration.Migration_NotificationsServer) error {
	ch, cancel, err := s.migrationController.Subscribe(ctx, request.SessionID)
	if err != nil {
		return err
	}
	defer cancel()

	logger := log.G(ctx).WithField(logfields.SessionID, request.SessionID)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case resp, ok := <-ch:
			if !ok {
				// Session terminated; close the stream cleanly.
				return nil
			}
			if err := server.Send(resp); err != nil {
				logger.WithError(err).Warn("send migration notification failed")
				return err
			}
		}
	}
}

// createDuplicateSocketInternal delegates to the migration controller to
// install the duplicated migration transport socket for the active session.
func (s *Service) createDuplicateSocketInternal(ctx context.Context, request *migration.CreateDuplicateSocketRequest) (*migration.CreateDuplicateSocketResponse, error) {
	if err := s.migrationController.RegisterDuplicateSocket(ctx, request.SessionID, request.ProtocolInfo); err != nil {
		return nil, err
	}
	return &migration.CreateDuplicateSocketResponse{}, nil
}

func (s *Service) patchMigratedContainerInternal(
	ctx context.Context,
	request *task.CreateTaskRequest,
	specAnnotations map[string]string,
	ct oci.KubernetesContainerType,
	sid string,
) (*task.CreateTaskResponse, error) {
	if err := s.migrationController.PatchResourcePaths(ctx, request, specAnnotations); err != nil {
		return nil, fmt.Errorf("patch migrated container %q: %w", request.ID, err)
	}

	delete(s.containerPodMapping, specAnnotations[annotations.LiveMigrationSourceContainerID])
	newPodID := sid
	if ct == oci.KubernetesContainerTypeSandbox {
		newPodID = request.ID
	}
	s.containerPodMapping[request.ID] = newPodID

	ctrCtrl, err := s.getContainerController(request.ID)
	if err != nil {
		return nil, fmt.Errorf("lookup migrated container %q: %w", request.ID, err)
	}
	initProc, err := ctrCtrl.GetProcess("")
	if err != nil {
		return nil, fmt.Errorf("get init process for migrated container %q: %w", request.ID, err)
	}

	s.send(&eventstypes.TaskCreate{
		ContainerID: request.ID,
		Bundle:      request.Bundle,
		Rootfs:      request.Rootfs,
		IO: &eventstypes.TaskIO{
			Stdin:    request.Stdin,
			Stdout:   request.Stdout,
			Stderr:   request.Stderr,
			Terminal: request.Terminal,
		},
		Pid: uint32(initProc.Pid()),
	})

	return &task.CreateTaskResponse{Pid: uint32(initProc.Pid())}, nil
}
