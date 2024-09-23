package taskserver

import (
	"context"
	"fmt"
	"runtime/pprof"

	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/emptypb"
)

type instrumentedService struct {
	inner task.TaskService
}

func NewInstrumentedService(inner task.TaskService) task.TaskService {
	return &instrumentedService{inner}
}

func (s *instrumentedService) Checkpoint(ctx context.Context, req *task.CheckpointTaskRequest) (resp *emptypb.Empty, err error) {
	op := "taskservice.Checkpoint"
	log.G(ctx).WithFields(logrus.Fields{
		"taskID": req.ID,
		"path":   req.Path,
	}).Infof("call to %s", op)
	defer log.G(ctx).Infof("call to %s complete", op)
	pprof.Do(ctx, pprof.Labels("rpc", op, "taskID", req.ID), func(ctx context.Context) {
		resp, err = s.inner.Checkpoint(ctx, req)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return resp, nil
}

func (s *instrumentedService) CloseIO(ctx context.Context, req *task.CloseIORequest) (resp *emptypb.Empty, err error) {
	op := "taskservice.CloseIO"
	log.G(ctx).WithFields(logrus.Fields{
		"taskID": req.ID,
		"execID": req.ExecID,
		"stdin":  req.Stdin,
	}).Infof("call to %s", op)
	defer log.G(ctx).Infof("call to %s complete", op)
	pprof.Do(ctx, pprof.Labels("rpc", op, "taskID", req.ID, "execID", req.ExecID), func(ctx context.Context) {
		resp, err = s.inner.CloseIO(ctx, req)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return resp, nil
}

func (s *instrumentedService) Connect(ctx context.Context, req *task.ConnectRequest) (resp *task.ConnectResponse, err error) {
	op := "taskservice.Connect"
	log.G(ctx).WithFields(logrus.Fields{
		"taskID": req.ID,
	}).Infof("call to %s", op)
	defer log.G(ctx).Infof("call to %s complete", op)
	pprof.Do(ctx, pprof.Labels("rpc", op, "taskID", req.ID), func(ctx context.Context) {
		resp, err = s.inner.Connect(ctx, req)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return resp, nil
}

func (s *instrumentedService) Create(ctx context.Context, req *task.CreateTaskRequest) (resp *task.CreateTaskResponse, err error) {
	op := "taskservice.Create"
	log.G(ctx).WithFields(logrus.Fields{
		"taskID": req.ID,
	}).Infof("call to %s", op)
	defer log.G(ctx).Infof("call to %s complete", op)
	pprof.Do(ctx, pprof.Labels("rpc", op, "taskID", req.ID), func(ctx context.Context) {
		resp, err = s.inner.Create(ctx, req)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return resp, nil
}

func (s *instrumentedService) Delete(ctx context.Context, req *task.DeleteRequest) (resp *task.DeleteResponse, err error) {
	op := "taskservice.Delete"
	log.G(ctx).WithFields(logrus.Fields{
		"taskID": req.ID,
		"execID": req.ExecID,
	}).Infof("call to %s", op)
	defer log.G(ctx).Infof("call to %s complete", op)
	pprof.Do(ctx, pprof.Labels("rpc", op, "taskID", req.ID, "execID", req.ExecID), func(ctx context.Context) {
		resp, err = s.inner.Delete(ctx, req)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return resp, nil
}

func (s *instrumentedService) Exec(ctx context.Context, req *task.ExecProcessRequest) (resp *emptypb.Empty, err error) {
	op := "taskservice.Exec"
	log.G(ctx).WithFields(logrus.Fields{
		"taskID": req.ID,
		"execID": req.ExecID,
	}).Infof("call to %s", op)
	defer log.G(ctx).Infof("call to %s complete", op)
	pprof.Do(ctx, pprof.Labels("rpc", op, "taskID", req.ID, "execID", req.ExecID), func(ctx context.Context) {
		resp, err = s.inner.Exec(ctx, req)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return resp, nil
}

func (s *instrumentedService) Kill(ctx context.Context, req *task.KillRequest) (resp *emptypb.Empty, err error) {
	op := "taskservice.Kill"
	log.G(ctx).WithFields(logrus.Fields{
		"taskID": req.ID,
		"execID": req.ExecID,
		"signal": req.Signal,
		"all":    req.All,
	}).Infof("call to %s", op)
	defer log.G(ctx).Infof("call to %s complete", op)
	pprof.Do(ctx, pprof.Labels("rpc", op, "taskID", req.ID, "execID", req.ExecID, "signal", fmt.Sprintf("%d", req.Signal), "all", fmt.Sprintf("%v", req.All)), func(ctx context.Context) {
		resp, err = s.inner.Kill(ctx, req)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return resp, nil
}

func (s *instrumentedService) Pause(ctx context.Context, req *task.PauseRequest) (resp *emptypb.Empty, err error) {
	op := "taskservice.Pause"
	log.G(ctx).WithFields(logrus.Fields{
		"taskID": req.ID,
	}).Infof("call to %s", op)
	defer log.G(ctx).Infof("call to %s complete", op)
	pprof.Do(ctx, pprof.Labels("rpc", op, "taskID", req.ID), func(ctx context.Context) {
		resp, err = s.inner.Pause(ctx, req)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return resp, nil
}

func (s *instrumentedService) Pids(ctx context.Context, req *task.PidsRequest) (resp *task.PidsResponse, err error) {
	op := "taskservice.Pids"
	log.G(ctx).WithFields(logrus.Fields{
		"taskID": req.ID,
	}).Infof("call to %s", op)
	defer log.G(ctx).Infof("call to %s complete", op)
	pprof.Do(ctx, pprof.Labels("rpc", op, "taskID", req.ID), func(ctx context.Context) {
		resp, err = s.inner.Pids(ctx, req)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return resp, nil
}

func (s *instrumentedService) ResizePty(ctx context.Context, req *task.ResizePtyRequest) (resp *emptypb.Empty, err error) {
	op := "taskservice.ResizePty"
	log.G(ctx).WithFields(logrus.Fields{
		"taskID": req.ID,
		"execID": req.ExecID,
	}).Infof("call to %s", op)
	defer log.G(ctx).Infof("call to %s complete", op)
	pprof.Do(ctx, pprof.Labels("rpc", op, "taskID", req.ID, "execID", req.ExecID), func(ctx context.Context) {
		resp, err = s.inner.ResizePty(ctx, req)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return resp, nil
}

func (s *instrumentedService) Resume(ctx context.Context, req *task.ResumeRequest) (resp *emptypb.Empty, err error) {
	op := "taskservice.Resume"
	log.G(ctx).WithFields(logrus.Fields{
		"taskID": req.ID,
	}).Infof("call to %s", op)
	defer log.G(ctx).Infof("call to %s complete", op)
	pprof.Do(ctx, pprof.Labels("rpc", op, "taskID", req.ID), func(ctx context.Context) {
		resp, err = s.inner.Resume(ctx, req)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return resp, nil
}

func (s *instrumentedService) Shutdown(ctx context.Context, req *task.ShutdownRequest) (resp *emptypb.Empty, err error) {
	op := "taskservice.Shutdown"
	log.G(ctx).WithFields(logrus.Fields{
		"taskID": req.ID,
		"now":    req.Now,
	}).Infof("call to %s", op)
	defer log.G(ctx).Infof("call to %s complete", op)
	pprof.Do(ctx, pprof.Labels("rpc", op, "taskID", req.ID, "now", fmt.Sprintf("%v", req.Now)), func(ctx context.Context) {
		resp, err = s.inner.Shutdown(ctx, req)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return resp, nil
}

func (s *instrumentedService) Start(ctx context.Context, req *task.StartRequest) (resp *task.StartResponse, err error) {
	op := "taskservice.Start"
	log.G(ctx).WithFields(logrus.Fields{
		"taskID": req.ID,
		"execID": req.ExecID,
	}).Infof("call to %s", op)
	defer log.G(ctx).Infof("call to %s complete", op)
	pprof.Do(ctx, pprof.Labels("rpc", op, "taskID", req.ID, "execID", req.ExecID), func(ctx context.Context) {
		resp, err = s.inner.Start(ctx, req)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return resp, nil
}

func (s *instrumentedService) State(ctx context.Context, req *task.StateRequest) (resp *task.StateResponse, err error) {
	op := "taskservice.State"
	log.G(ctx).WithFields(logrus.Fields{
		"taskID": req.ID,
		"execID": req.ExecID,
	}).Infof("call to %s", op)
	defer log.G(ctx).Infof("call to %s complete", op)
	pprof.Do(ctx, pprof.Labels("rpc", op, "taskID", req.ID, "execID", req.ExecID), func(ctx context.Context) {
		resp, err = s.inner.State(ctx, req)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return resp, nil
}

func (s *instrumentedService) Stats(ctx context.Context, req *task.StatsRequest) (resp *task.StatsResponse, err error) {
	op := "taskservice.Stats"
	log.G(ctx).WithFields(logrus.Fields{
		"taskID": req.ID,
	}).Infof("call to %s", op)
	defer log.G(ctx).Infof("call to %s complete", op)
	pprof.Do(ctx, pprof.Labels("rpc", op, "taskID", req.ID), func(ctx context.Context) {
		resp, err = s.inner.Stats(ctx, req)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return resp, nil
}

func (s *instrumentedService) Update(ctx context.Context, req *task.UpdateTaskRequest) (resp *emptypb.Empty, err error) {
	op := "taskservice.Update"
	log.G(ctx).WithFields(logrus.Fields{
		"taskID": req.ID,
	}).Infof("call to %s", op)
	defer log.G(ctx).Infof("call to %s complete", op)
	pprof.Do(ctx, pprof.Labels("rpc", op, "taskID", req.ID), func(ctx context.Context) {
		resp, err = s.inner.Update(ctx, req)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return resp, nil
}

func (s *instrumentedService) Wait(ctx context.Context, req *task.WaitRequest) (resp *task.WaitResponse, err error) {
	op := "taskservice.Wait"
	log.G(ctx).WithFields(logrus.Fields{
		"taskID": req.ID,
		"execID": req.ExecID,
	}).Infof("call to %s", op)
	defer log.G(ctx).Infof("call to %s complete", op)
	pprof.Do(ctx, pprof.Labels("rpc", op, "taskID", req.ID, "execID", req.ExecID), func(ctx context.Context) {
		resp, err = s.inner.Wait(ctx, req)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return resp, nil
}
