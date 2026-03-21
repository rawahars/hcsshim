//go:build windows

package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Microsoft/hcsshim/internal/controller/container"
	"github.com/Microsoft/hcsshim/internal/controller/network"
	"github.com/Microsoft/hcsshim/internal/controller/pod"
	"github.com/Microsoft/hcsshim/internal/controller/process"
	"github.com/Microsoft/hcsshim/internal/hcs"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/logfields"
	"github.com/Microsoft/hcsshim/internal/oci"
	"github.com/Microsoft/hcsshim/pkg/ctrdtaskapi"
	"github.com/containerd/containerd/api/runtime/task/v3"
	"github.com/containerd/errdefs"
	"github.com/containerd/typeurl/v2"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/emptypb"
)

// todo: mutex locking here or within controller?
// todo: send events
// todo: check if the vm is running

// getContainerController looks up the container controller for the given container ID.
// It resolves the container's pod via containerPodMapping, retrieves the pod controller,
// and then returns the container controller from the pod.
//
// The caller must hold s.mu.
func (s *Service) getContainerController(containerID string) (*container.Manager, error) {
	podID, ok := s.containerPodMapping[containerID]
	if !ok {
		return nil, fmt.Errorf("container %s not found: %w", containerID, errdefs.ErrNotFound)
	}

	podCtrl, ok := s.podControllers[podID]
	if !ok {
		return nil, fmt.Errorf("pod controller for pod %s not found: %w", podID, errdefs.ErrNotFound)
	}

	ctrCtrl, err := podCtrl.GetContainer(containerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get container controller for container %s in pod %s: %w", containerID, podID, err)
	}

	return ctrCtrl, nil
}

func (s *Service) stateInternal(_ context.Context, request *task.StateRequest) (*task.StateResponse, error) {
	s.mu.Lock()
	ctrCtrl, err := s.getContainerController(request.ID)
	if err != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("failed to find container for state request: %w", err)
	}

	proc, err := ctrCtrl.GetProcess(request.ExecID)
	if err != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("failed to get process (execID=%q) in container %s: %w", request.ExecID, request.ID, err)
	}
	s.mu.Unlock()

	return proc.Status(true), nil
}

func (s *Service) createInternal(ctx context.Context, request *task.CreateTaskRequest) (*task.CreateTaskResponse, error) {
	// Parse the OCI spec from the bundle to determine the sandbox type and ID.
	var spec specs.Spec
	f, err := os.Open(filepath.Join(request.Bundle, "config.json"))
	if err != nil {
		return nil, fmt.Errorf("failed to open config.json: %w", err)
	}
	if err := json.NewDecoder(f).Decode(&spec); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("failed to decode config.json: %w", err)
	}
	_ = f.Close()

	ct, sid, err := oci.GetSandboxTypeAndID(spec.Annotations)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var ctrCtrl *container.Manager

	switch ct {
	case oci.KubernetesContainerTypeSandbox:
		// This is a pod creation request. Create a new pod controller.
		if _, ok := s.podControllers[sid]; ok {
			return nil, fmt.Errorf("pod controller for pod %s already exists: %w", sid, errdefs.ErrAlreadyExists)
		}

		// todo: Move these checks to another method.
		if spec.Windows == nil || spec.Windows.Network == nil {
			return nil, fmt.Errorf("spec is missing required Windows network configuration: %w", errdefs.ErrInvalidArgument)
		}

		if len(spec.Windows.Network.EndpointList) > 0 {
			return nil, fmt.Errorf("spec has unsupported network configuration: endpoints should not be part of spec: %w", errdefs.ErrInvalidArgument)
		}

		podCtrl := pod.New(s.vmController, sid)

		err = podCtrl.SetupNetwork(ctx, &network.SetupOptions{
			NetworkNamespace:   spec.Windows.Network.NetworkNamespace,
			PolicyBasedRouting: s.sandboxOptions.PolicyBasedRouting,
		})
		if err != nil {
			// No cleanup on failure since containerd will send a Delete request.
			return nil, fmt.Errorf("failed to setup network for pod %s: %w", sid, err)
		}

		s.podControllers[sid] = podCtrl

		// Create a container within the pod with the same ID as the pod.
		ctrCtrl, err = podCtrl.NewContainer(request.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to create sandbox container %s in pod %s: %w", request.ID, sid, err)
		}

		s.containerPodMapping[request.ID] = sid

	case oci.KubernetesContainerTypeContainer:
		// This is a regular container creation request. Look up the existing pod.
		podCtrl, ok := s.podControllers[sid]
		if !ok {
			return nil, fmt.Errorf("pod controller for pod %s not found: %w", sid, errdefs.ErrNotFound)
		}

		ctrCtrl, err = podCtrl.NewContainer(request.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to create container %s in pod %s: %w", request.ID, sid, err)
		}

		s.containerPodMapping[request.ID] = sid

	default:
		return nil, fmt.Errorf("unsupported container type %q: %w", ct, errdefs.ErrInvalidArgument)
	}

	// Call Create on the container controller.
	if err := ctrCtrl.Create(ctx, &spec, request); err != nil {
		return nil, fmt.Errorf("failed to create container %s: %w", request.ID, err)
	}

	// Get the init process pid to return in the response.
	initProc, err := ctrCtrl.GetProcess("")
	if err != nil {
		return nil, fmt.Errorf("failed to get init process for container %s: %w", request.ID, err)
	}

	return &task.CreateTaskResponse{
		Pid: uint32(initProc.Pid()),
	}, nil
}

func (s *Service) startInternal(ctx context.Context, request *task.StartRequest) (*task.StartResponse, error) {
	s.mu.Lock()
	ctrCtrl, err := s.getContainerController(request.ID)
	if err != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("failed to find container for start request: %w", err)
	}
	s.mu.Unlock()

	resp := &task.StartResponse{}

	// If the start was meant for container,
	// call start on Container controller.
	if request.ExecID == "" {
		pid, err := ctrCtrl.Start(ctx)
		if err != nil {
			//todo: if start fails, we need to call delete/kill for cleanup.
			return nil, fmt.Errorf("failed to start container %s: %w", request.ID, err)
		}
		resp.Pid = pid
		return resp, nil
	}

	// If the start was meant for exec process,
	// call start on Process controller.
	s.mu.Lock()
	proc, err := ctrCtrl.GetProcess(request.ExecID)
	s.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("failed to get process (execID=%q) in container %s: %w", request.ExecID, request.ID, err)
	}

	p, err := proc.Start(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to start process (execID=%q) in container %s: %w", request.ExecID, request.ID, err)
	}
	resp.Pid = uint32(p)
	return resp, nil
}

func (s *Service) deleteInternal(_ context.Context, _ *task.DeleteRequest) (*task.DeleteResponse, error) {
	return nil, errdefs.ErrNotImplemented
}

func (s *Service) pidsInternal(ctx context.Context, request *task.PidsRequest) (*task.PidsResponse, error) {
	s.mu.Lock()
	ctrCtrl, err := s.getContainerController(request.ID)
	if err != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("failed to find container for pids request: %w", err)
	}
	s.mu.Unlock()

	pids, err := ctrCtrl.Pids(ctx)
	if err != nil {
		err = enrichNotFoundError(err)
		return nil, fmt.Errorf("failed to get pids for container %s: %w", request.ID, err)
	}

	return &task.PidsResponse{
		Processes: pids,
	}, nil
}

func (s *Service) pauseInternal(_ context.Context, _ *task.PauseRequest) (*emptypb.Empty, error) {
	return nil, errdefs.ErrNotImplemented
}

func (s *Service) resumeInternal(_ context.Context, _ *task.ResumeRequest) (*emptypb.Empty, error) {
	return nil, errdefs.ErrNotImplemented
}

func (s *Service) checkpointInternal(_ context.Context, _ *task.CheckpointTaskRequest) (*emptypb.Empty, error) {
	return nil, errdefs.ErrNotImplemented
}

func (s *Service) killInternal(_ context.Context, _ *task.KillRequest) (*emptypb.Empty, error) {
	return nil, errdefs.ErrNotImplemented
}

func (s *Service) execInternal(ctx context.Context, request *task.ExecProcessRequest) (*emptypb.Empty, error) {
	var spec specs.Process
	if err := json.Unmarshal(request.Spec.Value, &spec); err != nil {
		return nil, fmt.Errorf("request.Spec was not oci process: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ctrCtrl, err := s.getContainerController(request.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to find container for exec request: %w", err)
	}

	proc, err := ctrCtrl.NewProcess(ctx, request.ExecID)
	if err != nil {
		return nil, fmt.Errorf("failed to create new process (execID=%q) in container %s: %w", request.ExecID, request.ID, err)
	}

	if err := proc.Create(ctx, &process.CreateOptions{
		Spec:     &spec,
		Terminal: request.Terminal,
		Stdin:    request.Stdin,
		Stdout:   request.Stdout,
		Stderr:   request.Stderr,
	}); err != nil {
		return nil, fmt.Errorf("failed to create exec process (execID=%q) in container %s: %w", request.ExecID, request.ID, err)
	}

	return &emptypb.Empty{}, nil
}

func (s *Service) resizePtyInternal(ctx context.Context, request *task.ResizePtyRequest) (*emptypb.Empty, error) {
	s.mu.Lock()
	ctrCtrl, err := s.getContainerController(request.ID)
	if err != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("failed to find container for resize pty request: %w", err)
	}

	proc, err := ctrCtrl.GetProcess(request.ExecID)
	if err != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("failed to get process (execID=%q) in container %s: %w", request.ExecID, request.ID, err)
	}
	s.mu.Unlock()

	if err := proc.ResizeConsole(ctx, request.Width, request.Height); err != nil {
		return nil, fmt.Errorf("failed to resize pty for process (execID=%q) in container %s: %w", request.ExecID, request.ID, err)
	}

	return &emptypb.Empty{}, nil
}

func (s *Service) closeIOInternal(ctx context.Context, request *task.CloseIORequest) (*emptypb.Empty, error) {
	s.mu.Lock()
	ctrCtrl, err := s.getContainerController(request.ID)
	if err != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("failed to find container for close IO request: %w", err)
	}

	proc, err := ctrCtrl.GetProcess(request.ExecID)
	if err != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("failed to get process (execID=%q) in container %s: %w", request.ExecID, request.ID, err)
	}
	s.mu.Unlock()

	proc.CloseIO(ctx)

	return &emptypb.Empty{}, nil
}

func (s *Service) updateInternal(ctx context.Context, request *task.UpdateTaskRequest) (*emptypb.Empty, error) {
	if request.Resources == nil {
		return nil, fmt.Errorf("resources cannot be empty, updating container %s resources failed: %w", request.ID, errdefs.ErrInvalidArgument)
	}

	resources, err := typeurl.UnmarshalAny(request.Resources)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal resources for container %s update request: %w", request.ID, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if the ID in request matches any podID in podController map.
	// If so, this is a pod-level update — call Update on the VMController.
	if _, ok := s.podControllers[request.ID]; ok {
		if err := s.vmController.Update(ctx, resources, request.Annotations); err != nil {
			return nil, fmt.Errorf("failed to update VM resources for pod %s: %w", request.ID, err)
		}
		return &emptypb.Empty{}, nil
	}

	// Otherwise, find the container controller and call Update on it.
	ctrCtrl, err := s.getContainerController(request.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to update resources for container %s: %w", request.ID, err)
	}

	if err := ctrCtrl.Update(ctx, resources, request.Annotations); err != nil {
		return nil, fmt.Errorf("failed to update resources for container %s: %w", request.ID, err)
	}

	return &emptypb.Empty{}, nil
}

func (s *Service) waitInternal(ctx context.Context, request *task.WaitRequest) (*task.WaitResponse, error) {
	// todo: Check if the wait is for the pod container itself.
	s.mu.Lock()
	ctrCtrl, err := s.getContainerController(request.ID)
	if err != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("failed to find container for wait request: %w", err)
	}
	s.mu.Unlock()

	// An empty ExecID means the caller is waiting for the container itself
	// (i.e. the init process + full teardown). Wait on the container
	// controller, which blocks until the container reaches StateTerminated
	// and has finished the teardown.
	if request.ExecID == "" {
		ctrCtrl.Wait(ctx)
	}

	// Get the process controller associated with the ExecID.
	s.mu.Lock()
	proc, err := ctrCtrl.GetProcess(request.ExecID)
	if err != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("failed to get process (execID=%q) in container %s: %w", request.ExecID, request.ID, err)
	}
	s.mu.Unlock()

	// If the request was to wait on a non-init process,
	// call Wait on the process controller itself.
	if request.ExecID != "" {
		proc.Wait(ctx)
	}

	// Get the Process status.
	status := proc.Status(true)

	return &task.WaitResponse{
		ExitStatus: status.ExitStatus,
		ExitedAt:   status.ExitedAt,
	}, nil
}

func (s *Service) statsInternal(ctx context.Context, request *task.StatsRequest) (*task.StatsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Look up the container controller. This works for both pod-level requests
	// (where a container with the same ID as the pod always exists) and regular
	// container requests.
	ctrCtrl, err := s.getContainerController(request.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to find container for stats request: %w", err)
	}

	ctrStats, err := ctrCtrl.Stats(ctx)
	if err != nil {
		err = enrichNotFoundError(err)
		return nil, fmt.Errorf("failed to get container stats for %s: %w", request.ID, err)
	}

	// Fetch and attach VM stats only for pod-level requests.
	if _, isPod := s.podControllers[request.ID]; isPod {
		vmStats, err := s.vmController.Stats(ctx)
		if err != nil {
			err = enrichNotFoundError(err)
			return nil, fmt.Errorf("failed to get VM stats: %w", err)
		}
		ctrStats.VM = vmStats
	}

	// Marshal the stats into an Any for the response.
	anyStats, err := typeurl.MarshalAny(ctrStats)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal stats: %w", err)
	}

	return &task.StatsResponse{
		Stats: typeurl.MarshalProto(anyStats),
	}, nil
}

func (s *Service) shutdownInternal(ctx context.Context, request *task.ShutdownRequest) (*emptypb.Empty, error) {
	// Because this shim strictly implements the Sandbox API,
	// the TaskService no longer has the authority to shut down the shim process.
	// Shim teardown is completely deferred to SandboxService.ShutdownSandbox.

	// Simply log the call for debugging purposes and return.
	log.G(ctx).WithFields(logrus.Fields{
		logfields.SandboxID: s.sandboxID,
		logfields.ID:        request.ID,
	}).Debug("Ignoring TaskService.Shutdown request")

	return &emptypb.Empty{}, nil
}

func enrichNotFoundError(err error) error {
	isNotFound := errdefs.IsNotFound(err) ||
		hcs.IsNotExist(err) ||
		hcs.IsOperationInvalidState(err) ||
		hcs.IsAccessIsDenied(err) ||
		hcs.IsErrorInvalidHandle(err)
	if isNotFound {
		return fmt.Errorf("%w: %w", errdefs.ErrNotFound, err)
	}
	return err
}

func IsUpdateResourcesTypeSupported(data interface{}) bool {
	switch data.(type) {
	case *specs.LinuxResources:
	case *ctrdtaskapi.PolicyFragment:
	default:
		return false
	}
	return true
}
