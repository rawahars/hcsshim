//go:build windows

package service

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/Microsoft/hcsshim/internal/controller/vm"
	"github.com/Microsoft/hcsshim/internal/shimdiag"

	"github.com/containerd/errdefs"
)

// diagExecInHostInternal is the implementation for DiagExecInHost.
//
// It is used to create an exec session into the hosting UVM.
func (s *Service) diagExecInHostInternal(ctx context.Context, request *shimdiag.ExecProcessRequest) (*shimdiag.ExecProcessResponse, error) {
	ec, err := s.vmController.ExecIntoHost(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to exec into host: %w", err)
	}

	return &shimdiag.ExecProcessResponse{ExitCode: int32(ec)}, nil
}

func (s *Service) diagTasksInternal(ctx context.Context, request *shimdiag.TasksRequest) (*shimdiag.TasksResponse, error) {
	if s.vmController.State() != vm.StateRunning {
		return nil, fmt.Errorf("cannot list tasks when vm is not running: %w", errdefs.ErrFailedPrecondition)
	}

	// Originally this method was intended to be used in a single pod setup and therefore,
	// we do not specify a TaskID in the request. Since our shim can support multiple pods,
	// we will modify this functionality so that we will return all tasks running in the UVM,
	// regardless of which pod they belong to.

	resp := &shimdiag.TasksResponse{}

	// todo: think about concurrency handling here.
	// Do we want to lock for entire duration or not.
	// This is a diagnostic method and therefore, should not have
	// performance implications in prod.
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, podCtrl := range s.podControllers {
		containers, err := podCtrl.ListContainers()
		if err != nil {
			return nil, fmt.Errorf("failed to list containers: %w", err)
		}

		for containerID, ctrCtrl := range containers {
			t := &shimdiag.Task{ID: containerID}

			if request.Execs {
				processes, err := ctrCtrl.ListProcesses()
				if err != nil {
					return nil, fmt.Errorf("failed to list processes for container %s: %w", containerID, err)
				}

				for _, proc := range processes {
					status := proc.Status(false)
					t.Execs = append(t.Execs, &shimdiag.Exec{
						ID:    status.ExecID,
						State: status.Status.String(),
					})
				}
			}

			resp.Tasks = append(resp.Tasks, t)
		}
	}

	return resp, nil
}

func (s *Service) diagShareInternal(_ context.Context, _ *shimdiag.ShareRequest) (*shimdiag.ShareResponse, error) {
	return nil, errdefs.ErrNotImplemented
}

func (s *Service) diagStacksInternal(ctx context.Context) (*shimdiag.StacksResponse, error) {
	if s.vmController.State() != vm.StateRunning {
		return nil, fmt.Errorf("cannot dump stacks when vm is not running: %w", errdefs.ErrFailedPrecondition)
	}

	buf := make([]byte, 4096)
	for {
		buf = buf[:runtime.Stack(buf, true)]
		if len(buf) < cap(buf) {
			break
		}
		buf = make([]byte, 2*len(buf))
	}

	timedCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resp := &shimdiag.StacksResponse{Stacks: string(buf)}
	stacks, err := s.vmController.DumpStacks(timedCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to dump stacks: %w", err)
	}

	resp.GuestStacks = stacks
	return resp, nil
}
