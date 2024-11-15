package taskserver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	runhcsopts "github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/options"
	"github.com/Microsoft/hcsshim/internal/cmd"
	"github.com/Microsoft/hcsshim/internal/core"
	"github.com/Microsoft/hcsshim/internal/ctrdpub"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/protobuf"
	"github.com/containerd/containerd/runtime"
	"github.com/containerd/typeurl/v2"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/emptypb"
)

type service struct {
	sandbox   *Sandbox
	m         sync.Mutex
	closeCh   chan<- struct{}
	closeOnce sync.Once
	publisher *ctrdpub.Publisher
	migState  *migrationState
}

func NewService(closeCh chan<- struct{}, publisher *ctrdpub.Publisher) *service {
	return &service{
		closeCh:   closeCh,
		publisher: publisher,
	}
}

func (s *service) Checkpoint(ctx context.Context, req *task.CheckpointTaskRequest) (*emptypb.Empty, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *service) CloseIO(ctx context.Context, req *task.CloseIORequest) (*emptypb.Empty, error) {
	c, _, err := s.sandbox.get(req.ID, req.ExecID)
	if err != nil {
		return nil, err
	}
	c.(core.ProcessLike).CloseIO(ctx)
	return &emptypb.Empty{}, nil
}

func (s *service) Connect(ctx context.Context, req *task.ConnectRequest) (*task.ConnectResponse, error) {
	resp := &task.ConnectResponse{ShimPid: uint32(os.Getpid())}
	if s.sandbox == nil {
		return resp, nil
	}
	if req.ID == s.sandbox.TaskID {
		resp.TaskPid = s.sandbox.Pid
		return resp, nil
	} else if t, ok := s.sandbox.Tasks[req.ID]; ok {
		resp.TaskPid = t.Pid
		return resp, nil
	}
	return nil, fmt.Errorf("task not found: %s", req.ID)
}

func (s *service) Create(ctx context.Context, req *task.CreateTaskRequest) (*task.CreateTaskResponse, error) {
	shimOpts := &runhcsopts.Options{}
	if req.Options != nil {
		v, err := typeurl.UnmarshalAny(req.Options)
		if err != nil {
			return nil, err
		}
		shimOpts = v.(*runhcsopts.Options)
	}

	if req.Terminal && req.Stderr != "" {
		return nil, errors.Wrap(errdefs.ErrFailedPrecondition, "if using terminal, stderr must be empty")
	}

	if s.sandbox == nil {
		switch shimOpts.BundleType {
		case runhcsopts.BundleType_BUNDLE_OCI:
			logrus.Info("creating oci sandbox")
			sandbox, err := s.newOCISandbox(ctx, shimOpts, req)
			if err != nil {
				return nil, fmt.Errorf("OCI sandbox creation failed: %w", err)
			}
			s.sandbox = sandbox
		case runhcsopts.BundleType_BUNDLE_POD_LM:
			logrus.Info("creating lm sandbox")
			s.newSandboxLM(ctx, shimOpts, req)
		default:
			return nil, fmt.Errorf("unsupported bundle type: %s", shimOpts.BundleType)
		}
	} else {
		switch shimOpts.BundleType {
		case runhcsopts.BundleType_BUNDLE_OCI:
			if err := s.sandbox.newOCIContainer(ctx, shimOpts, req); err != nil {
				return nil, err
			}
		case runhcsopts.BundleType_BUNDLE_CONTAINER_RESTORE:
			if err := s.newRestoreContainer(ctx, shimOpts, req); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unsupported bundle type: %s", shimOpts.BundleType)
		}
	}

	resp := &task.CreateTaskResponse{
		Pid: 0,
	}

	if err := s.publisher.PublishEvent(ctx, runtime.TaskCreateEventTopic, &events.TaskCreate{
		ContainerID: req.ID,
		Bundle:      req.Bundle,
		Rootfs:      req.Rootfs,
		IO: &events.TaskIO{
			Stdin:    req.Stdin,
			Stdout:   req.Stdout,
			Stderr:   req.Stderr,
			Terminal: req.Terminal,
		},
		Pid: 0,
	}); err != nil {
		log.G(ctx).WithError(err).Info("PublishEvent failed")
	}
	return resp, nil
}

func (s *service) Delete(ctx context.Context, req *task.DeleteRequest) (*task.DeleteResponse, error) {
	_, state, err := s.sandbox.get(req.ID, req.ExecID)
	if err != nil {
		return nil, err
	}
	if err := s.publisher.PublishEvent(ctx, runtime.TaskDeleteEventTopic, &events.TaskDelete{
		ContainerID: state.TaskID,
		ID:          state.ExecID,
		Pid:         state.Pid,
		ExitStatus:  state.ExitStatus,
		ExitedAt:    protobuf.ToTimestamp(state.ExitedAt),
	}); err != nil {
		log.G(ctx).WithError(err).Info("PublishEvent failed")
	}
	return &task.DeleteResponse{
		Pid:        state.Pid,
		ExitStatus: state.ExitStatus,
		ExitedAt:   protobuf.ToTimestamp(state.ExitedAt),
	}, nil
}

func (s *service) Exec(ctx context.Context, req *task.ExecProcessRequest) (*emptypb.Empty, error) {
	t, _, err := s.sandbox.get(req.ID, "")
	if err != nil {
		return nil, err
	}
	c := t.(core.Ctr)
	var spec specs.Process
	if err := json.Unmarshal(req.Spec.Value, &spec); err != nil {
		return nil, err
	}
	io, err := cmd.NewUpstreamIO(ctx, req.ID, req.Stdout, req.Stderr, req.Stdin, req.Terminal, 0)
	if err != nil {
		return nil, err
	}
	p, err := c.CreateProcess(ctx, &core.ProcessConfig{
		ID:   req.ExecID,
		Spec: &spec,
		IO:   io,
	})
	if err != nil {
		return nil, err
	}
	task := s.sandbox.Tasks[req.ID]
	e := &Exec{
		Process: p,
		State:   newExecState(req, task.Bundle),
	}
	task.Execs[req.ExecID] = e
	if err := s.publisher.PublishEvent(ctx, runtime.TaskExecAddedEventTopic, &events.TaskExecAdded{
		ContainerID: req.ID,
		ExecID:      req.ExecID,
	}); err != nil {
		log.G(ctx).WithError(err).Info("PublishEvent failed")
	}
	return &emptypb.Empty{}, nil
}

func (s *service) Kill(ctx context.Context, req *task.KillRequest) (*emptypb.Empty, error) {
	if req.ID == s.sandbox.TaskID {
		if req.ExecID != "" {
			return nil, fmt.Errorf("killing sandbox execs is not supported")
		}
		return &emptypb.Empty{}, s.sandbox.Sandbox.Terminate(ctx)
	}
	task, ok := s.sandbox.Tasks[req.ID]
	if !ok {
		return nil, fmt.Errorf("task not found: %s", req.ID)
	}
	if req.All {
		if req.ExecID != "" {
			return nil, fmt.Errorf("ExecID must be empty when All is set")
		}
		for _, e := range task.Execs {
			if err := e.Process.Signal(ctx, int(req.Signal)); err != nil {
				return nil, fmt.Errorf("signal exec %s: %w", e.ExecID, err)
			}
		}
		return &emptypb.Empty{}, nil
	}
	var p core.ProcessLike = task.Ctr
	if req.ExecID != "" {
		e, ok := task.Execs[req.ExecID]
		if !ok {
			return nil, fmt.Errorf("exec not found: %s", req.ExecID)
		}
		p = e.Process
	}
	if err := p.Signal(ctx, int(req.Signal)); err != nil {
		return nil, fmt.Errorf("signal exec %s: %w", req.ExecID, err)
	}
	return &emptypb.Empty{}, nil
}

func (s *service) Pause(ctx context.Context, req *task.PauseRequest) (*emptypb.Empty, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *service) Pids(ctx context.Context, req *task.PidsRequest) (*task.PidsResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *service) ResizePty(ctx context.Context, req *task.ResizePtyRequest) (*emptypb.Empty, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *service) Resume(ctx context.Context, req *task.ResumeRequest) (*emptypb.Empty, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *service) Shutdown(ctx context.Context, req *task.ShutdownRequest) (*emptypb.Empty, error) {
	if req.ID == s.sandbox.TaskID {
		s.closeOnce.Do(func() { close(s.closeCh) })
	}
	return &emptypb.Empty{}, nil
}

func (s *service) Start(ctx context.Context, req *task.StartRequest) (*task.StartResponse, error) {
	c, state, err := s.sandbox.get(req.ID, req.ExecID)
	if err != nil {
		return nil, err
	}
	if err := c.Start(ctx); err != nil {
		return nil, err
	}
	pid := uint32(c.Pid())
	state.setStarted(pid)
	if req.ExecID == "" {
		if err := s.publisher.PublishEvent(ctx, runtime.TaskStartEventTopic, &events.TaskStart{
			ContainerID: req.ID,
			Pid:         pid,
		}); err != nil {
			log.G(ctx).WithError(err).Info("PublishEvent failed")
		}
	} else {
		if err := s.publisher.PublishEvent(ctx, runtime.TaskExecStartedEventTopic, &events.TaskExecStarted{
			ContainerID: req.ID,
			ExecID:      req.ExecID,
			Pid:         pid,
		}); err != nil {
			log.G(ctx).WithError(err).Info("PublishEvent failed")
		}
	}
	go func() {
		waitCh := make(chan error)
		go func() {
			waitCh <- c.Wait(context.Background())
		}()
		select {
		case err := <-waitCh:
			logrus.WithFields(logrus.Fields{
				"taskID":        req.ID,
				"execID":        req.ExecID,
				logrus.ErrorKey: err,
			}).Error("failed waiting for task exit")
		case <-s.sandbox.waitCtx.Done():
			logrus.WithFields(logrus.Fields{
				"taskID": req.ID,
				"execID": req.ExecID,
			}).Info("aborted task wait")
			return
		}
		state.setExited(uint32(c.Status().ExitCode()))
		if err := s.publisher.PublishEvent(ctx, runtime.TaskExitEventTopic, &events.TaskExit{
			ContainerID: state.TaskID,
			ID:          req.ExecID,
			Pid:         state.Pid,
			ExitStatus:  state.ExitStatus,
			ExitedAt:    protobuf.ToTimestamp(state.ExitedAt),
		}); err != nil {
			log.G(ctx).WithError(err).Info("PublishEvent failed")
		}
		close(state.waitCh)
	}()
	return &task.StartResponse{Pid: pid}, nil
}

func (s *service) State(ctx context.Context, req *task.StateRequest) (*task.StateResponse, error) {
	_, state, err := s.sandbox.get(req.ID, req.ExecID)
	if err != nil {
		return nil, err
	}
	return &task.StateResponse{
		ID:         state.TaskID,
		Bundle:     state.Bundle,
		Pid:        state.Pid,
		Status:     state.Status,
		Stdin:      state.Stdin,
		Stdout:     state.Stdout,
		Stderr:     state.Stderr,
		Terminal:   state.Terminal,
		ExitStatus: state.ExitStatus,
		ExitedAt:   protobuf.ToTimestamp(state.ExitedAt),
		ExecID:     state.ExecID,
	}, nil
}

func (s *service) Stats(ctx context.Context, req *task.StatsRequest) (*task.StatsResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *service) Update(ctx context.Context, req *task.UpdateTaskRequest) (*emptypb.Empty, error) {
	resources, err := typeurl.UnmarshalAny(req.Resources)
	if err != nil {
		return nil, err
	}
	switch data := resources.(type) {
	default:
		return nil, fmt.Errorf("unrecognized update resource type: %T", data)
	}
	return &emptypb.Empty{}, nil
}

func (s *service) Wait(ctx context.Context, req *task.WaitRequest) (*task.WaitResponse, error) {
	_, state, err := s.sandbox.get(req.ID, req.ExecID)
	if err != nil {
		return nil, err
	}
	select {
	case <-state.waitCh:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return &task.WaitResponse{
		ExitStatus: state.ExitStatus,
		ExitedAt:   protobuf.ToTimestamp(state.ExitedAt),
	}, nil
}
