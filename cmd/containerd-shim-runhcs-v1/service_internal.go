//go:build windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	task "github.com/containerd/containerd/api/runtime/task/v2"
	containerd_v1_types "github.com/containerd/containerd/api/types/task"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	typeurl "github.com/containerd/typeurl/v2"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	runhcsopts "github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/options"
	"github.com/Microsoft/hcsshim/internal/extendedtask"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/oci"
	"github.com/Microsoft/hcsshim/internal/shimdiag"
)

var empty = &emptypb.Empty{}

// getPod returns the pod with requested podID or TaskID.
//
// We return `errdefs.ErrFailedPrecondition` if -
// - The id does not correspond to a task or a pod
// - The id corresponds to a standalone task
func (s *service) getPod(podOrTaskId string) (shimPod, error) {
	rawPod, _ := s.pods.Load(podOrTaskId)
	if rawPod == nil {
		// Check if the requested podOrTaskId matches the task id.
		raw, ok := s.tasks.Load(podOrTaskId)
		if !ok {
			return nil, errors.Wrapf(errdefs.ErrFailedPrecondition, "task with id: '%s' must be created first", s.tid)
		}

		switch val := raw.(type) {
		case shimPod:
			return val, nil
		case shimTask:
			return nil, errors.Wrapf(errdefs.ErrFailedPrecondition, "standalone task found with id: '%s'", s.tid)
		default:
			return nil, fmt.Errorf("invalid type for task with id: '%s'", podOrTaskId)
		}
	}
	return rawPod.(shimPod), nil
}

// getTask returns a task matching `tid` or else returns an error. This properly
// handles a task in a pod or a singular task shim.
//
// If `tid` is not found will return `errdefs.ErrNotFound`.
func (s *service) getTask(tid string) (shimTask, error) {
	raw, ok := s.tasks.Load(tid)
	if !ok {
		return nil, errors.Wrapf(errdefs.ErrNotFound, "task with id: '%s' not found", tid)
	}

	switch val := raw.(type) {
	case shimPod:
		return val.GetTask(tid)
	case shimTask:
		// When its not a sandbox only the init task is a valid id.
		if s.tid != tid {
			return nil, errors.Wrapf(errdefs.ErrNotFound, "task with id: '%s' is not found", s.tid)
		}
		return val, nil
	default:
		return nil, fmt.Errorf("invalid type for task with id: '%s'", tid)
	}
}

func (s *service) stateInternal(ctx context.Context, req *task.StateRequest) (*task.StateResponse, error) {
	t, err := s.getTask(req.ID)
	if err != nil {
		return nil, err
	}
	e, err := t.GetExec(req.ExecID)
	if err != nil {
		return nil, err
	}
	return e.Status(), nil
}

func (s *service) createInternal(ctx context.Context, req *task.CreateTaskRequest) (*task.CreateTaskResponse, error) {
	setupDebuggerEvent()

	shimOpts := &runhcsopts.Options{}
	if req.Options != nil {
		v, err := typeurl.UnmarshalAny(req.Options)
		if err != nil {
			return nil, err
		}
		shimOpts = v.(*runhcsopts.Options)

		if entry := log.G(ctx); entry.Logger.IsLevelEnabled(logrus.DebugLevel) {
			entry.WithField("options", log.Format(ctx, shimOpts)).Debug("parsed runhcs runtime options")
		}
	}
	// ideally the runtime options would be set appropriately, but cannot guarantee that
	// instead, distinguish between empty and misconfigured options
	emptyShimOpts := req.Options == nil || proto.Equal(shimOpts, &runhcsopts.Options{})

	var spec specs.Spec
	f, err := os.Open(filepath.Join(req.Bundle, "config.json"))
	if err != nil {
		return nil, err
	}
	if err := json.NewDecoder(f).Decode(&spec); err != nil {
		f.Close()
		return nil, err
	}
	f.Close()

	spec = oci.UpdateSpecFromOptions(spec, shimOpts)
	// expand annotations after defaults have been loaded in from options
	err = oci.ProcessAnnotations(ctx, &spec)
	// since annotation expansion is used to toggle security features
	// raise it rather than suppress and move on
	if err != nil {
		return nil, errors.Wrap(err, "unable to process OCI Spec annotations")
	}

	// If sandbox isolation is set to hypervisor, make sure the HyperV option
	// is filled in. This lessens the burden on Containerd to parse our shims
	// options if we can set this ourselves.
	if isolation := shimOpts.GetSandboxIsolation(); isolation == runhcsopts.Options_HYPERVISOR {
		if spec.Windows == nil {
			spec.Windows = &specs.Windows{}
		}
		if spec.Windows.HyperV == nil {
			spec.Windows.HyperV = &specs.WindowsHyperV{}
		}
	} else if !emptyShimOpts && oci.IsIsolated(&spec) {
		// non-empty runtime options, but invalid isolation
		return nil, fmt.Errorf("invalid runtime sandbox isolation (%s) for hypervisor isolated OCI spec", isolation.String())
	}

	if !emptyShimOpts {
		// validate runtime platform
		plat, err := platforms.Parse(shimOpts.GetSandboxPlatform())
		if err != nil {
			return nil, fmt.Errorf("invalid runtime sandbox platform: %w", err)
		}
		switch plat.OS {
		case "windows":
			if oci.IsLCOW(&spec) {
				return nil, fmt.Errorf("non-empty Linux config in OCI spec for Windows sandbox platform: %s", platforms.Format(plat))
			}
		case "linux":
			if oci.IsWCOW(&spec) {
				return nil, fmt.Errorf("empty Linux config in OCI spec for Linux sandbox platform: %s", platforms.Format(plat))
			}
		default:
			return nil, fmt.Errorf("unknown runtime sandbox platform OS: %s", platforms.Format(plat))
		}
	}

	// This is a Windows Argon make sure that we have a Root filled in.
	if spec.Windows.HyperV == nil {
		if spec.Root == nil {
			spec.Root = &specs.Root{}
		}
	}

	if req.Terminal && req.Stderr != "" {
		return nil, errors.Wrap(errdefs.ErrFailedPrecondition, "if using terminal, stderr must be empty")
	}

	resp := &task.CreateTaskResponse{}
	s.cl.Lock()
	if s.isSandbox {
		// Get the sandbox annotations and derive the sandbox-id.
		_, sid, err := oci.GetSandboxTypeAndID(spec.Annotations)
		if err != nil {
			return nil, err
		}

		pod, err := s.getPod(sid)
		if err == nil {
			// The POD sandbox was previously created. Unlock and forward to the POD
			s.cl.Unlock()
			t, err := pod.CreateTask(ctx, req, &spec)
			if err != nil {
				return nil, err
			}

			// Save the task in the task map.
			s.tasks.Store(req.ID, pod)

			e, _ := t.GetExec("")
			resp.Pid = uint32(e.Pid())
			return resp, nil
		}

		if s.sandbox.phase == sandboxUnknown {
			// Sandbox is not managed by the Sandbox Controller and therefore,
			// needs to be tied with this pod lifecycle.
			s.sandbox.phase = sandboxPodManaged
		} else if s.sandbox.phase == sandboxCreated || s.sandbox.phase == sandboxTerminated {
			return nil, errors.Wrap(errdefs.ErrFailedPrecondition, "sandbox not running")
		}

		if s.sandbox.phase == sandboxStarted {
			pod, err = createPodWithSandbox(ctx, s.events, req, &spec, s.sandbox.host, s.sandbox.id)
		} else {
			pod, err = createPod(ctx, s.events, req, &spec)
		}

		if err != nil {
			s.cl.Unlock()
			return nil, err
		}

		t, _ := pod.GetTask(req.ID)
		e, _ := t.GetExec("")
		resp.Pid = uint32(e.Pid())

		// Store the pod and task in their corresponding maps.
		s.pods.Store(pod.ID(), pod)
		s.tasks.Store(req.ID, pod)

	} else {
		t, err := newHcsStandaloneTask(ctx, s.events, req, &spec)
		if err != nil {
			s.cl.Unlock()
			return nil, err
		}
		e, _ := t.GetExec("")
		resp.Pid = uint32(e.Pid())
		s.tasks.Store(req.ID, t)
	}
	s.cl.Unlock()
	return resp, nil
}

func (s *service) startInternal(ctx context.Context, req *task.StartRequest) (*task.StartResponse, error) {
	t, err := s.getTask(req.ID)
	if err != nil {
		return nil, err
	}
	e, err := t.GetExec(req.ExecID)
	if err != nil {
		return nil, err
	}
	err = e.Start(ctx)
	if err != nil {
		return nil, err
	}
	return &task.StartResponse{
		Pid: uint32(e.Pid()),
	}, nil
}

func (s *service) deleteInternal(ctx context.Context, req *task.DeleteRequest) (*task.DeleteResponse, error) {
	t, err := s.getTask(req.ID)
	if err != nil {
		return nil, err
	}

	pid, exitStatus, exitedAt, err := t.DeleteExec(ctx, req.ExecID)
	if err != nil {
		return nil, err
	}

	// if the delete is for a task and not an exec, remove the pod sandbox's reference to the task
	if s.isSandbox && req.ExecID == "" {
		p, err := s.getPod(req.ID)
		if err != nil {
			return nil, errors.Wrapf(err, "could not get pod %q to delete task %q", s.tid, req.ID)
		}
		err = p.DeleteTask(ctx, req.ID)
		if err != nil {
			return nil, fmt.Errorf("could not delete task %q in pod %q: %w", req.ID, s.tid, err)
		}
	}
	// TODO: check if the pod's workload tasks is empty, and, if so, reset p.taskOrPod to nil

	return &task.DeleteResponse{
		Pid:        uint32(pid),
		ExitStatus: exitStatus,
		ExitedAt:   timestamppb.New(exitedAt),
	}, nil
}

func (s *service) pidsInternal(ctx context.Context, req *task.PidsRequest) (*task.PidsResponse, error) {
	t, err := s.getTask(req.ID)
	if err != nil {
		return nil, err
	}
	pids, err := t.Pids(ctx)
	if err != nil {
		return nil, err
	}
	processes := make([]*containerd_v1_types.ProcessInfo, len(pids))
	for i, p := range pids {
		a, err := typeurl.MarshalAny(p)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to marshal ProcessDetails for process: %s, task: %s", p.ExecID, req.ID)
		}
		proc := &containerd_v1_types.ProcessInfo{
			Pid:  p.ProcessID,
			Info: typeurl.MarshalProto(a),
		}
		processes[i] = proc
	}
	return &task.PidsResponse{
		Processes: processes,
	}, nil
}

func (s *service) pauseInternal(ctx context.Context, req *task.PauseRequest) (*emptypb.Empty, error) {
	/*
		s.events <- cdevent{
			topic: runtime.TaskPausedEventTopic,
			event: &eventstypes.TaskPaused{
				req.ID,
			},
		}
	*/
	return nil, errdefs.ErrNotImplemented
}

func (s *service) resumeInternal(ctx context.Context, req *task.ResumeRequest) (*emptypb.Empty, error) {
	/*
		s.events <- cdevent{
			topic: runtime.TaskResumedEventTopic,
			event: &eventstypes.TaskResumed{
				req.ID,
			},
		}
	*/
	return nil, errdefs.ErrNotImplemented
}

func (s *service) checkpointInternal(ctx context.Context, req *task.CheckpointTaskRequest) (*emptypb.Empty, error) {
	return nil, errdefs.ErrNotImplemented
}

func (s *service) killInternal(ctx context.Context, req *task.KillRequest) (*emptypb.Empty, error) {
	if s.isSandbox {
		pod, err := s.getPod(req.ID)
		if err != nil {
			return nil, errors.Wrapf(errdefs.ErrNotFound, "%v: task with id: '%s' not found", err, req.ID)
		}
		// Send it to the POD and let it cascade on its own through all tasks.
		err = pod.KillTask(ctx, req.ID, req.ExecID, req.Signal, req.All)
		if err != nil {
			return nil, err
		}
		return empty, nil
	}
	t, err := s.getTask(req.ID)
	if err != nil {
		return nil, err
	}
	// Send it to the task and let it cascade on its own through all exec's
	err = t.KillExec(ctx, req.ExecID, req.Signal, req.All)
	if err != nil {
		return nil, err
	}
	return empty, nil
}

func (s *service) execInternal(ctx context.Context, req *task.ExecProcessRequest) (*emptypb.Empty, error) {
	t, err := s.getTask(req.ID)
	if err != nil {
		return nil, err
	}
	if req.Terminal && req.Stderr != "" {
		return nil, errors.Wrap(errdefs.ErrFailedPrecondition, "if using terminal, stderr must be empty")
	}
	var spec specs.Process
	if err := json.Unmarshal(req.Spec.Value, &spec); err != nil {
		return nil, errors.Wrap(err, "request.Spec was not oci process")
	}
	err = t.CreateExec(ctx, req, &spec)
	if err != nil {
		return nil, err
	}
	return empty, nil
}

func (s *service) diagExecInHostInternal(ctx context.Context, req *shimdiag.ExecProcessRequest) (*shimdiag.ExecProcessResponse, error) {
	if req.Terminal && req.Stderr != "" {
		return nil, errors.Wrap(errdefs.ErrFailedPrecondition, "if using terminal, stderr must be empty")
	}

	var t shimTask
	var ec int
	var err error

	// If the sandbox is managed via sandbox APIs,
	// we will call the internal methods directly.
	if s.sandbox.phase == sandboxStarted {
		ec, err = execInHost(ctx, req, s.sandbox.host)
		if err != nil {
			return nil, err
		}
	} else {
		t, err = s.getTask(s.tid)
		if err != nil {
			return nil, err
		}
		ec, err = t.ExecInHost(ctx, req)
		if err != nil {
			return nil, err
		}
	}

	return &shimdiag.ExecProcessResponse{ExitCode: int32(ec)}, nil
}

func (s *service) diagShareInternal(ctx context.Context, req *shimdiag.ShareRequest) (*shimdiag.ShareResponse, error) {
	// If the sandbox is managed via sandbox APIs,
	// we will call the internal methods directly.
	if s.sandbox.phase == sandboxStarted {
		if err := shareOnHost(ctx, req, s.sandbox.host); err != nil {
			return nil, err
		}
		return &shimdiag.ShareResponse{}, nil
	}

	t, err := s.getTask(s.tid)
	if err != nil {
		return nil, err
	}
	if err := t.Share(ctx, req); err != nil {
		return nil, err
	}
	return &shimdiag.ShareResponse{}, nil
}

func (s *service) diagListExecs(task shimTask) ([]*shimdiag.Exec, error) {
	var sdExecs []*shimdiag.Exec
	execs, err := task.ListExecs()
	if err != nil {
		return nil, err
	}
	for _, exec := range execs {
		sdExecs = append(sdExecs, &shimdiag.Exec{ID: exec.ID(), State: string(exec.State())})
	}
	return sdExecs, nil
}

func (s *service) diagTasksInternal(ctx context.Context, req *shimdiag.TasksRequest) (_ *shimdiag.TasksResponse, err error) {

	resp := &shimdiag.TasksResponse{}
	if s.isSandbox {
		s.pods.Range(func(podId, rawPod any) bool {
			p, ok := rawPod.(shimPod)
			if !ok {
				err = errors.New("failed to assert pod")
				return false
			}

			tasks, err := p.ListTasks()
			for _, task := range tasks {
				t := &shimdiag.Task{ID: task.ID()}
				if req.Execs {
					t.Execs, err = s.diagListExecs(task)
					if err != nil {
						return false
					}
				}
				resp.Tasks = append(resp.Tasks, t)
			}

			return true
		})
		if err != nil {
			return nil, err
		}

		return resp, nil
	}

	s.tasks.Range(func(taskId, raw any) bool {
		t, ok := raw.(shimTask)
		if !ok {
			err = errors.New("failed to assert task")
		}

		task := &shimdiag.Task{ID: t.ID()}
		if req.Execs {
			task.Execs, err = s.diagListExecs(t)
			if err != nil {
				return false
			}
		}

		resp.Tasks = []*shimdiag.Task{task}
		return false
	})

	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (s *service) resizePtyInternal(ctx context.Context, req *task.ResizePtyRequest) (*emptypb.Empty, error) {
	t, err := s.getTask(req.ID)
	if err != nil {
		return nil, err
	}
	e, err := t.GetExec(req.ExecID)
	if err != nil {
		return nil, err
	}
	err = e.ResizePty(ctx, req.Width, req.Height)
	if err != nil {
		return nil, err
	}
	return empty, nil
}

func (s *service) closeIOInternal(ctx context.Context, req *task.CloseIORequest) (*emptypb.Empty, error) {
	t, err := s.getTask(req.ID)
	if err != nil {
		return nil, err
	}
	e, err := t.GetExec(req.ExecID)
	if err != nil {
		return nil, err
	}
	err = e.CloseIO(ctx, req.Stdin)
	if err != nil {
		return nil, err
	}
	return empty, nil
}

func (s *service) updateInternal(ctx context.Context, req *task.UpdateTaskRequest) (*emptypb.Empty, error) {
	if req.Resources == nil {
		return nil, errors.Wrapf(errdefs.ErrInvalidArgument, "resources cannot be empty, updating container %s resources failed", req.ID)
	}
	t, err := s.getTask(req.ID)
	if err != nil {
		return nil, err
	}
	if err := t.Update(ctx, req); err != nil {
		return nil, err
	}
	return empty, nil
}

func (s *service) waitInternal(ctx context.Context, req *task.WaitRequest) (*task.WaitResponse, error) {
	t, err := s.getTask(req.ID)
	if err != nil {
		return nil, err
	}
	var state *task.StateResponse
	if req.ExecID != "" {
		e, err := t.GetExec(req.ExecID)
		if err != nil {
			return nil, err
		}
		state = e.Wait()
	} else {
		state = t.Wait()
	}
	return &task.WaitResponse{
		ExitStatus: state.ExitStatus,
		ExitedAt:   state.ExitedAt,
	}, nil
}

func (s *service) statsInternal(ctx context.Context, req *task.StatsRequest) (*task.StatsResponse, error) {
	t, err := s.getTask(req.ID)
	if err != nil {
		return nil, err
	}
	stats, err := t.Stats(ctx)
	if err != nil {
		return nil, err
	}
	any, err := typeurl.MarshalAny(stats)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal Statistics for task: %s", req.ID)
	}
	return &task.StatsResponse{Stats: typeurl.MarshalProto(any)}, nil
}

func (s *service) connectInternal(ctx context.Context, req *task.ConnectRequest) (*task.ConnectResponse, error) {
	// We treat the shim/task as the same pid on the Windows host.
	pid := uint32(os.Getpid())
	return &task.ConnectResponse{
		ShimPid: pid,
		TaskPid: pid,
	}, nil
}

func (s *service) shutdownInternal(ctx context.Context, req *task.ShutdownRequest) (*emptypb.Empty, error) {
	// Because a pod shim hosts multiple tasks only the init task can issue the
	// shutdown request.
	if req.ID != s.tid {
		return empty, nil
	}

	s.shutdownOnce.Do(func() {
		// TODO: should taskOrPod be deleted/set to nil?
		// TODO: is there any extra leftovers of the shimTask/Pod to clean? ie: verify all handles are closed?
		s.gracefulShutdown = !req.Now
		close(s.shutdown)
	})

	return empty, nil
}

func (s *service) computeProcessorInfoInternal(ctx context.Context, req *extendedtask.ComputeProcessorInfoRequest) (*extendedtask.ComputeProcessorInfoResponse, error) {
	t, err := s.getTask(req.ID)
	if err != nil {
		return nil, err
	}
	info, err := t.ProcessorInfo(ctx)
	if err != nil {
		return nil, err
	}
	return &extendedtask.ComputeProcessorInfoResponse{
		Count: info.count,
	}, nil
}
