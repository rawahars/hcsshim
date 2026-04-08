//go:build windows && lcow

package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Microsoft/hcsshim/internal/controller/linuxcontainer"
	"github.com/Microsoft/hcsshim/internal/controller/network"
	"github.com/Microsoft/hcsshim/internal/controller/pod"
	"github.com/Microsoft/hcsshim/internal/controller/process"
	"github.com/Microsoft/hcsshim/internal/hcs"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/logfields"
	"github.com/Microsoft/hcsshim/internal/oci"
	"github.com/Microsoft/hcsshim/pkg/ctrdtaskapi"
	eventstypes "github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/containerd/errdefs"
	"github.com/containerd/typeurl/v2"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/emptypb"
)

// todo: mutex locking here or within controller?
// todo: check if the vm is running

// getContainerController looks up the container controller for the given container ID.
// It resolves the container's pod via containerPodMapping, retrieves the pod controller,
// and then returns the container controller from the pod.
//
// The caller must hold s.mu.
func (s *Service) getContainerController(containerID string) (*linuxcontainer.Controller, error) {
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

	var ctrCtrl *linuxcontainer.Controller

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

		podCtrl := pod.New(sid, s.vmController)

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
	if err := ctrCtrl.Create(
		ctx,
		&spec,
		request,
		&linuxcontainer.CreateContainerOpts{
			IsScratchEncryptionEnabled: s.sandboxOptions.EnableScratchEncryption,
		},
	); err != nil {
		return nil, fmt.Errorf("failed to create container %s: %w", request.ID, err)
	}

	// Get the init process pid to return in the response.
	initProc, err := ctrCtrl.GetProcess("")
	if err != nil {
		return nil, fmt.Errorf("failed to get init process for container %s: %w", request.ID, err)
	}

	// Publish the TaskCreate event to notify containerd that the container has been created.
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
		pid, err := ctrCtrl.Start(ctx, s.send)
		if err != nil {
			//todo: if start fails, we need to call delete/kill for cleanup.
			return nil, fmt.Errorf("failed to start container %s: %w", request.ID, err)
		}
		resp.Pid = pid

		// Publish the TaskStart event for the init process.
		s.send(&eventstypes.TaskStart{
			ContainerID: request.ID,
			Pid:         pid,
		})

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

	p, err := proc.Start(ctx, s.send)
	if err != nil {
		return nil, fmt.Errorf("failed to start process (execID=%q) in container %s: %w", request.ExecID, request.ID, err)
	}
	resp.Pid = uint32(p)

	// Publish the TaskExecStarted event for the exec process.
	s.send(&eventstypes.TaskExecStarted{
		ContainerID: request.ID,
		ExecID:      request.ExecID,
		Pid:         uint32(p),
	})

	return resp, nil
}

// deleteInternal deletes a process, container, or pod sandbox entry depending on the request.
func (s *Service) deleteInternal(ctx context.Context, request *task.DeleteRequest) (*task.DeleteResponse, error) {
	s.mu.Lock()

	// Look up the container controller for the target ID.
	ctrCtrl, err := s.getContainerController(request.ID)
	if err != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("failed to find container for delete request: %w", err)
	}
	s.mu.Unlock()

	// Delete the process from the container controller.
	// For the init process this is request.ExecID == "".
	status, err := ctrCtrl.DeleteProcess(ctx, request.ExecID)
	if err != nil {
		return nil, fmt.Errorf("failed to delete process (execID=%q) in container %s: %w", request.ExecID, request.ID, err)
	}

	// Build the response from the process status returned by DeleteProcess.
	resp := &task.DeleteResponse{
		Pid:        status.Pid,
		ExitStatus: status.ExitStatus,
		ExitedAt:   status.ExitedAt,
	}

	// Publish the TaskDelete event to notify containerd the process/task has been deleted.
	s.send(&eventstypes.TaskDelete{
		ContainerID: request.ID,
		ID:          request.ExecID,
		Pid:         status.Pid,
		ExitStatus:  status.ExitStatus,
		ExitedAt:    status.ExitedAt,
	})

	// If this was an exec process deletion, we are done.
	if request.ExecID != "" {
		return resp, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	podID := s.containerPodMapping[request.ID]

	// If the container ID matches a pod ID, this is the sandbox container
	// being torn down. Verify all workload containers have been cleaned up,
	// tear down the network, remove the sandbox container from the pod, and
	// then remove the pod entry from the controllers map.
	if podCtrl, isPod := s.podControllers[request.ID]; isPod {
		// Ensure no workload containers remain in the pod. The only container
		// left should be the sandbox container itself (request.ID).
		remaining := podCtrl.ListContainers()
		delete(remaining, request.ID) // exclude the sandbox container itself
		if len(remaining) > 0 {
			return nil, fmt.Errorf("cannot delete sandbox container %s: %d workload container(s) still exist in the pod: %w",
				request.ID, len(remaining), errdefs.ErrFailedPrecondition)
		}

		// Tear down the pod network before removing the pod controller.
		if err := podCtrl.TeardownNetwork(ctx); err != nil {
			return nil, fmt.Errorf("failed to teardown network for pod %s: %w", request.ID, err)
		}

		// Remove the sandbox container from the pod's internal container map.
		if err := podCtrl.DeleteContainer(request.ID); err != nil {
			return nil, fmt.Errorf("failed to delete sandbox container %s from pod: %w", request.ID, err)
		}

		delete(s.podControllers, request.ID)
		delete(s.containerPodMapping, request.ID)
		return resp, nil
	}

	// Regular (non-sandbox) container: delete the container from the owning
	// pod controller first, then remove the mapping.
	podCtrl, ok := s.podControllers[podID]
	if !ok {
		return nil, fmt.Errorf("pod controller for pod %s not found while deleting container %s: %w", podID, request.ID, errdefs.ErrNotFound)
	}

	if err := podCtrl.DeleteContainer(request.ID); err != nil {
		return nil, fmt.Errorf("failed to delete container %s from pod %s: %w", request.ID, podID, err)
	}

	delete(s.containerPodMapping, request.ID)

	return resp, nil
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

func (s *Service) killInternal(ctx context.Context, request *task.KillRequest) (*emptypb.Empty, error) {
	s.mu.Lock()
	ctrCtrl, err := s.getContainerController(request.ID)
	if err != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("failed to find container for kill request: %w", err)
	}

	// If "all" is set and this is a sandbox (pod) container, collect all
	// workload containers so we can fan out the kill to the entire pod.
	var workloadContainers map[string]*linuxcontainer.Controller
	if request.All {
		if podCtrl, isPod := s.podControllers[request.ID]; isPod {
			workloadContainers = podCtrl.ListContainers()
			// Exclude the sandbox container — it is killed below.
			delete(workloadContainers, request.ID)
		}
	}
	s.mu.Unlock()

	// Fan out kill to all workload containers and the target container concurrently.
	killGroup := errgroup.Group{}
	for _, workloadCtr := range workloadContainers {
		killGroup.Go(func() error {
			return workloadCtr.KillProcess(ctx, request.ExecID, request.Signal, request.All)
		})
	}
	killGroup.Go(func() error {
		return ctrCtrl.KillProcess(ctx, request.ExecID, request.Signal, request.All)
	})

	if err = killGroup.Wait(); err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
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

	// Publish the TaskExecAdded event to notify containerd that a new exec has been created.
	s.send(&eventstypes.TaskExecAdded{
		ContainerID: request.ID,
		ExecID:      request.ExecID,
	})

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

	switch resources.(type) {
	case *specs.LinuxResources:
	case *ctrdtaskapi.PolicyFragment:
	default:
		return nil, fmt.Errorf("unsupported resource type")
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

	if err := ctrCtrl.Update(ctx, resources); err != nil {
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
