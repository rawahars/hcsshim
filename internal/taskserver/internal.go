package taskserver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	runhcsopts "github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/options"
	"github.com/Microsoft/hcsshim/internal/cmd"
	"github.com/Microsoft/hcsshim/internal/core"
	"github.com/Microsoft/hcsshim/internal/core/linuxvm"
	"github.com/Microsoft/hcsshim/internal/layers"
	"github.com/Microsoft/hcsshim/internal/oci"
	"github.com/containerd/containerd/api/runtime/task/v2"
	containerd_v1_types "github.com/containerd/containerd/api/types/task"
	taskapi "github.com/containerd/containerd/api/types/task"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
)

type State struct {
	TaskID     string
	ExecID     string
	Bundle     string
	Stdin      string
	Stdout     string
	Stderr     string
	Terminal   bool
	Pid        uint32
	Status     taskapi.Status
	ExitStatus uint32
	ExitedAt   time.Time
	waitCh     chan struct{}
}

func newState(taskID, execID, stdin, stdout, stderr string, terminal bool, bundle string) *State {
	return &State{
		TaskID:     taskID,
		ExecID:     execID,
		Stdin:      stdin,
		Stdout:     stdout,
		Stderr:     stderr,
		Terminal:   terminal,
		Pid:        0,
		Status:     containerd_v1_types.Status_CREATED,
		ExitStatus: 0,
		ExitedAt:   time.Unix(0, 0),
		Bundle:     bundle,
		waitCh:     make(chan struct{}),
	}
}

func newTaskState(req *task.CreateTaskRequest) *State {
	return newState(req.ID, "", req.Stdin, req.Stdout, req.Stderr, req.Terminal, req.Bundle)
}

func newExecState(req *task.ExecProcessRequest, bundle string) *State {
	return newState(req.ID, req.ExecID, req.Stdin, req.Stdout, req.Stderr, req.Terminal, bundle)
}

func (s *State) setStarted(pid uint32) {
	s.Pid = pid
	s.Status = containerd_v1_types.Status_RUNNING
}

func (s *State) setExited(code uint32) {
	s.Pid = 0
	s.ExitStatus = code
	s.ExitedAt = time.Now()
	s.Status = containerd_v1_types.Status_STOPPED
}

type Sandbox struct {
	*State
	Sandbox core.Sandbox
	m       sync.Mutex
	Tasks   map[string]*Task
}

func (s *Sandbox) get(taskID, execID string) (core.GenericCompute, *State, error) {
	if taskID == s.TaskID {
		return s.Sandbox, s.State, nil
	}
	task, ok := s.Tasks[taskID]
	if !ok {
		return nil, nil, fmt.Errorf("task not found: %s", taskID)
	}
	if execID == "" {
		return task.Ctr, task.State, nil
	}
	exec, ok := task.Execs[execID]
	if !ok {
		return nil, nil, fmt.Errorf("exec not found: %s", execID)
	}
	return exec.Process, exec.State, nil
}

func (s *Sandbox) startSave(ctx context.Context, path string) (any, error) {
	mig, ok := s.Sandbox.(core.Migratable)
	if !ok {
		return nil, fmt.Errorf("sandbox does not support migration")
	}
	if err := mig.Save(ctx, filepath.Join(path, "sandbox")); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("not implemented")
}

func (s *Sandbox) completeSave(ctx context.Context) error {
	return fmt.Errorf("not implemented")
}

func (s *Sandbox) newOCIContainer(ctx context.Context, shimOpts *runhcsopts.Options, req *task.CreateTaskRequest) (err error) {
	spec, err := getOCISpec(ctx, req.Bundle, shimOpts)
	if err != nil {
		return err
	}

	var layerFolders []string
	if spec.Windows != nil {
		layerFolders = spec.Windows.LayerFolders
	}
	if err := layers.ValidateRootfsAndLayers(req.Rootfs, layerFolders); err != nil {
		return err
	}
	l, err := layers.GetLCOWLayers(req.Rootfs, layerFolders)
	if err != nil {
		return err
	}
	l2 := layers.GetLCOWLayers2(l)

	io, err := cmd.NewUpstreamIO(ctx, req.ID, req.Stdout, req.Stderr, req.Stdin, req.Terminal, 5*time.Second)
	if err != nil {
		return err
	}

	ctr, err := s.Sandbox.CreateLinuxContainer(ctx, &core.LinuxCtrConfig{
		ID:     req.ID,
		Layers: l2,
		Spec:   spec,
		IO:     io,
	})
	if err != nil {
		return err
	}

	s.Tasks[req.ID] = &Task{
		State: newTaskState(req),
		Ctr:   ctr,
		Execs: make(map[string]*Exec),
	}

	return nil
}

type Task struct {
	*State
	Ctr   core.Ctr
	m     sync.Mutex
	Execs map[string]*Exec
}

type Exec struct {
	*State
	m       sync.Mutex
	Process core.Process
}

func (s *service) newOCISandbox(ctx context.Context, shimOpts *runhcsopts.Options, req *task.CreateTaskRequest) (_ *Sandbox, err error) {
	spec, err := getOCISpec(ctx, req.Bundle, shimOpts)
	if err != nil {
		return nil, err
	}

	var layerFolders []string
	if spec.Windows != nil {
		layerFolders = spec.Windows.LayerFolders
	}
	if err := layers.ValidateRootfsAndLayers(req.Rootfs, layerFolders); err != nil {
		return nil, err
	}
	l, err := layers.GetLCOWLayers(req.Rootfs, layerFolders)
	if err != nil {
		return nil, err
	}
	l2 := layers.GetLCOWLayers2(l)

	sandbox, err := linuxvm.NewSandbox(ctx, req.ID, l2, spec)
	if err != nil {
		return nil, err
	}

	return &Sandbox{
		Sandbox: sandbox,
		Tasks:   make(map[string]*Task),
		State:   newTaskState(req),
	}, nil
}

func getOCISpec(ctx context.Context, bundle string, shimOpts *runhcsopts.Options) (*specs.Spec, error) {
	rawSpec, err := os.ReadFile(filepath.Join(bundle, "config.json"))
	if err != nil {
		return nil, err
	}
	var spec specs.Spec
	if err := json.Unmarshal(rawSpec, &spec); err != nil {
		return nil, err
	}
	spec = oci.UpdateSpecFromOptions(spec, shimOpts)
	//expand annotations after defaults have been loaded in from options
	// since annotation expansion is used to toggle security features
	// raise it rather than suppress and move on
	if err := oci.ProcessAnnotations(ctx, &spec); err != nil {
		return nil, errors.Wrap(err, "unable to process OCI Spec annotations")
	}
	// If sandbox isolation is set to hypervisor, make sure the HyperV option
	// is filled in. This lessens the burden on Containerd to parse our shims
	// options if we can set this ourselves.
	if shimOpts.SandboxIsolation == runhcsopts.Options_HYPERVISOR {
		if spec.Windows == nil {
			spec.Windows = &specs.Windows{}
		}
		if spec.Windows.HyperV == nil {
			spec.Windows.HyperV = &specs.WindowsHyperV{}
		}
	}
	return &spec, nil
}
