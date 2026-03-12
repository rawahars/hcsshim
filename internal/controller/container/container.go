//go:build windows

package container

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	runhcsopts "github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/options"
	"github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/stats"
	"github.com/Microsoft/hcsshim/internal/controller/process"
	"github.com/Microsoft/hcsshim/internal/controller/vm"
	"github.com/Microsoft/hcsshim/internal/gcs"
	"github.com/Microsoft/hcsshim/internal/hcs"
	"github.com/Microsoft/hcsshim/internal/hcs/schema1"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/layers"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/oci"
	"github.com/Microsoft/hcsshim/internal/vm/guestmanager"
	"github.com/containerd/containerd/api/runtime/task/v3"
	containerdtypes "github.com/containerd/containerd/api/types/task"
	"github.com/containerd/errdefs"
	"github.com/containerd/typeurl/v2"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Manager is the concrete implementation of Controller.
// It is the leaf node of the component hierarchy: it holds OCI-derived specs,
// drives the device controllers, and communicates with the GCS via guestmanager.
type Manager struct {
	mu sync.Mutex

	// containerID is the unique identifier for this container.
	containerID string

	// vmHandle provides access to the underlying VM's host and guest surfaces
	// and is used to wait for the VM to exit.
	// This is a subset interface of [vm.Controller] interface.
	vmHandle vm.Handle

	// guestMgr is used to create and manage the GCS container entity.
	guestMgr guestmanager.Manager

	container *gcs.Container

	// processes maps exec IDs to their process controllers.
	// The init process is stored with exec ID "".
	processes map[string]*process.Manager

	ioRetryTimeout time.Duration
}

var _ Controller = (*Manager)(nil)

// New creates a ready-to-use Manager.
func New(
	containerID string,
	vmHandle vm.Handle,
	guestMgr guestmanager.Manager,
) *Manager {
	return &Manager{
		containerID: containerID,
		vmHandle:    vmHandle,
		guestMgr:    guestMgr,
		processes:   make(map[string]*process.Manager),
	}
}

func (m *Manager) ID() string {
	return m.containerID
}

func (m *Manager) Create(ctx context.Context, opts *task.CreateTaskRequest) error {
	var err error

	// Parse the OCI spec from the request.
	var spec specs.Spec
	f, err := os.Open(filepath.Join(opts.Bundle, "config.json"))
	if err != nil {
		return fmt.Errorf("failed to open config.json: %w", err)
	}
	if err := json.NewDecoder(f).Decode(&spec); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to decode config.json: %w", err)
	}
	_ = f.Close()

	// Parse the runtime options from the request.
	// todo: create a helper method to parse runhcsoptions.
	shimOpts := &runhcsopts.Options{}
	if opts.Options != nil {
		v, err := typeurl.UnmarshalAny(opts.Options)
		if err != nil {
			return fmt.Errorf("failed to unmarshal options: %w", err)
		}
		shimOpts = v.(*runhcsopts.Options)

		if entry := log.G(ctx); entry.Logger.IsLevelEnabled(logrus.DebugLevel) {
			entry.WithField("options", log.Format(ctx, shimOpts)).Debug("parsed runhcs runtime options")
		}
	}

	spec = oci.UpdateSpecFromOptions(spec, shimOpts)
	// expand annotations after defaults have been loaded in from options
	err = oci.ProcessAnnotations(ctx, spec.Annotations)
	// since annotation expansion is used to toggle security features
	// raise it rather than suppress and move on
	if err != nil {
		return fmt.Errorf("unable to process OCI Spec annotations: %w", err)
	}

	// todo: do a validation to ensure that Linux or Windows sections in spec are there.

	// todo: move above spec logic into oci builder.

	// Parse layers.
	var wcowLayers layers.WCOWLayers
	var lcowLayers *layers.LCOWLayers
	var layerFolders []string
	if spec.Windows != nil {
		layerFolders = spec.Windows.LayerFolders
	}
	if spec.Linux != nil {
		lcowLayers, err = layers.ParseLCOWLayers(opts.Rootfs, layerFolders)
	} else {
		wcowLayers, err = layers.ParseWCOWLayers(opts.Rootfs, layerFolders)
	}
	if err != nil {
		return err
	}

	_ = wcowLayers
	_ = lcowLayers

	// todo: Parse the specs to create UVM host modification settings and guest side GCS requests.
	// Also creates the gcs document which needs to be passed along to GCS.

	// todo: Perform the host and guest requests

	// todo: call into gm to create the actual container with the gcs document.

	// Create the initial process controller with exec ID "".
	initProcess := process.New(m.containerID, "", m.container)

	// Default to an infinite timeout (zero value)
	if shimOpts != nil {
		m.ioRetryTimeout = time.Duration(shimOpts.IoRetryTimeoutInSec) * time.Second
	}

	err = initProcess.Create(ctx, &process.CreateOptions{
		Bundle:              opts.Bundle,
		Spec:                spec.Process,
		Terminal:            opts.Terminal,
		Stdin:               opts.Stdin,
		Stdout:              opts.Stdout,
		Stderr:              opts.Stderr,
		IoRetryTimeoutInSec: m.ioRetryTimeout,
	})
	if err != nil {
		return fmt.Errorf("failed to create init process: %w", err)
	}
	m.processes[""] = initProcess

	// todo: send task create event

	return nil
}

func (m *Manager) Start(ctx context.Context) (uint32, error) {
	// todo: call into gm to start the container in the guest.

	pid, err := m.processes[""].Start(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to start init process: %w", err)
	}

	// todo: if start fails, we terminate the container.

	// todo: send task start event
	return uint32(pid), nil
}

func (m *Manager) Update(ctx context.Context, resources interface{}, annotations map[string]string) error {
	//TODO implement me
	panic("implement me")
}

func (m *Manager) NewProcess(execID string) *process.Manager {
	// todo: check that the container is running.
	// todo: check that the execID doesn't already exist.
	return process.New(m.containerID, execID, m.container)
}

func (m *Manager) GetProcess(execID string) (*process.Manager, error) {
	p, ok := m.processes[execID]
	if !ok {
		return nil, fmt.Errorf("process with exec ID %s not found", execID)
	}
	return p, nil
}

func (m *Manager) ListProcesses() (map[string]*process.Manager, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make(map[string]*process.Manager, len(m.processes))
	for id, p := range m.processes {
		result[id] = p
	}
	return result, nil
}

func (m *Manager) Pids(ctx context.Context) ([]*containerdtypes.ProcessInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Map all tracked exec's to pid/exec-id
	pidMap := make(map[int]string)
	for execID, p := range m.processes {
		pidMap[p.Pid()] = execID
	}

	// Get the guest pids
	props, err := m.container.Properties(ctx, schema1.PropertyTypeProcessList)
	if err != nil {
		if isStatsNotFound(err) {
			return nil, fmt.Errorf("failed to fetch pids: %s: %w", err, errdefs.ErrNotFound)
		}
		return nil, err
	}

	// Build ProcessDetails for each process in the guest
	processes := make([]*containerdtypes.ProcessInfo, len(props.ProcessList))
	for i, p := range props.ProcessList {
		pd := &runhcsopts.ProcessDetails{
			ImageName:                    p.ImageName,
			CreatedAt:                    timestamppb.New(p.CreateTimestamp),
			KernelTime_100Ns:             p.KernelTime100ns,
			MemoryCommitBytes:            p.MemoryCommitBytes,
			MemoryWorkingSetPrivateBytes: p.MemoryWorkingSetPrivateBytes,
			MemoryWorkingSetSharedBytes:  p.MemoryWorkingSetSharedBytes,
			ProcessID:                    p.ProcessId,
			UserTime_100Ns:               p.KernelTime100ns,
		}
		if eid, ok := pidMap[int(p.ProcessId)]; ok {
			pd.ExecID = eid
		}

		a, err := typeurl.MarshalAny(pd)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ProcessDetails for process: %s, container: %s: %w", pd.ExecID, m.containerID, err)
		}
		processes[i] = &containerdtypes.ProcessInfo{
			Pid:  pd.ProcessID,
			Info: typeurl.MarshalProto(a),
		}
	}
	return processes, nil
}

func (m *Manager) Stats(ctx context.Context) (*stats.Statistics, error) {
	s := &stats.Statistics{}
	props, err := m.container.PropertiesV2(ctx, hcsschema.PTStatistics)
	if err != nil {
		if isStatsNotFound(err) {
			return nil, fmt.Errorf("failed to fetch stats: %s: %w", err, errdefs.ErrNotFound)
		}
		return nil, err
	}

	if props != nil {
		s.Container = parseContainerStats(props)
	}

	return s, nil
}

// isStatsNotFound returns true if the err corresponds to a scenario
// where statistics cannot be retrieved or found
func isStatsNotFound(err error) bool {
	return errdefs.IsNotFound(err) ||
		hcs.IsNotExist(err) ||
		hcs.IsOperationInvalidState(err) ||
		hcs.IsAccessIsDenied(err) ||
		hcs.IsErrorInvalidHandle(err)
}
