//go:build windows

package container

import (
	"context"
	"fmt"
	"sync"
	"time"

	runhcsopts "github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/options"
	"github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/stats"
	builder "github.com/Microsoft/hcsshim/internal/builder/oci/lcow"
	"github.com/Microsoft/hcsshim/internal/controller/process"
	"github.com/Microsoft/hcsshim/internal/gcs"
	"github.com/Microsoft/hcsshim/internal/hcs/schema1"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/layers"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/logfields"
	"github.com/Microsoft/hcsshim/internal/vm/guestmanager"
	"github.com/Microsoft/hcsshim/internal/vm/vmutils"
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
	// This is provided by containerd.
	containerID string

	// gcsContainerID is the identifier for the container used
	// while interacting with GCS.
	gcsContainerID string

	// guestMgr is used to create and manage the GCS container entity.
	guestMgr guestmanager.Manager

	container *gcs.Container

	state State

	// terminatedCh is closed exactly once when the container reaches
	// StateTerminated. All callers of Wait block on this channel, and
	// closing it unblocks every waiter simultaneously — the standard
	// Go broadcast pattern.
	terminatedCh chan struct{}

	// processes maps exec IDs to their process controllers.
	// The init process is stored with exec ID "".
	processes map[string]*process.Manager

	ioRetryTimeout time.Duration
}

var _ Controller = (*Manager)(nil)

// New creates a ready-to-use Manager.
func New(
	containerID string,
	guestMgr guestmanager.Manager,
) *Manager {
	// Generate a unique container ID which will be provided to and
	// used by GCS.
	gcsContainerID := vmutils.GenerateID()

	return &Manager{
		containerID:    containerID,
		gcsContainerID: gcsContainerID,
		guestMgr:       guestMgr,
		processes:      make(map[string]*process.Manager),
		state:          StateNotCreated,
		terminatedCh:   make(chan struct{}),
	}
}

func (m *Manager) ID() string {
	return m.containerID
}

func (m *Manager) Create(ctx context.Context, spec *specs.Spec, opts *task.CreateTaskRequest) error {
	ctx, _ = log.WithContext(ctx, logrus.WithFields(logrus.Fields{
		logfields.ContainerID:    m.containerID,
		logfields.GCSContainerID: m.gcsContainerID,
		logfields.Operation:      "Create Container",
	}))

	var err error

	// Parse the runtime options from the request.
	shimOpts, err := vmutils.UnmarshalRuntimeOptions(ctx, opts.Options)
	if err != nil {
		return fmt.Errorf("failed to unmarshal runtime options: %w", err)
	}

	// Update and validate the spec.
	err = builder.UpdateOCISpec(ctx, spec, shimOpts)
	if err != nil {
		return fmt.Errorf("failed to update OCI spec: %w", err)
	}

	// Parse layers.
	// todo: Move this logic into OS specific files.
	var wcowLayers layers.WCOWLayers
	var lcowLayers *layers.LCOWLayers

	layerFolders := spec.Windows.LayerFolders

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

	// todo: add drivers first. Consider the same for VM too.
	// todo: Perform the host requests.
	// todo: Perform the guest side requests.
	// todo: call into gm to create the actual container with the gcs document.

	// Default to an infinite timeout (zero value)
	if shimOpts != nil {
		m.ioRetryTimeout = time.Duration(shimOpts.IoRetryTimeoutInSec) * time.Second
	}

	// Create the initial process controller with exec ID "".
	initProcess := process.New(m.containerID, "", m.container, m.ioRetryTimeout)

	err = initProcess.Create(ctx, &process.CreateOptions{
		Bundle:   opts.Bundle,
		Spec:     spec.Process, // todo: for wcow, add this. skip for lcow.
		Terminal: opts.Terminal,
		Stdin:    opts.Stdin,
		Stdout:   opts.Stdout,
		Stderr:   opts.Stderr,
	})
	if err != nil {
		return fmt.Errorf("failed to create init process: %w", err)
	}
	m.processes[""] = initProcess

	// todo: send task create event

	return nil
}

func (m *Manager) Start(ctx context.Context) (uint32, error) {
	ctx, _ = log.WithContext(ctx, logrus.WithFields(logrus.Fields{
		logfields.ContainerID:    m.containerID,
		logfields.GCSContainerID: m.gcsContainerID,
		logfields.Operation:      "Start Container",
	}))

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.state == StateRunning {
		log.G(ctx).Infof("container is already running")
	}

	if m.state != StateCreated {
		return 1, fmt.Errorf("container %s is in invalid state %s for start: %w", m.ID(), m.state, errdefs.ErrFailedPrecondition)
	}

	// Start the container.
	err := m.container.Start(ctx)
	if err != nil {
		m.state = StateInvalid
		return 1, fmt.Errorf("failed to start container %s: %w", m.ID(), err)
	}

	// Get the init process and call start on the same.
	pid, err := m.processes[""].Start(ctx)
	if err != nil {
		m.state = StateInvalid
		return 1, fmt.Errorf("failed to start init process: %w", err)
	}

	m.state = StateRunning

	go m.handleInitProcessExit(ctx, m.processes[""])

	return uint32(pid), nil
}

// handleInitProcessExit blocks until the init process exits, then tears down
// the container and marks it terminated.
// Must be run as a goroutine.
func (m *Manager) handleInitProcessExit(ctx context.Context, initProcess process.Controller) {
	// Detach from the caller's context so upstream cancellation/timeout does
	// not abort the background teardown.
	ctx = context.WithoutCancel(ctx)

	// Block until the init process exits.
	initProcess.Wait(ctx)

	m.mu.Lock()
	if m.state == StateStopped || m.state == StateTerminated {
		// todo: check for invalid state and other states.
		log.G(ctx).Warnf("container %s is already in stopped state", m.ID())
		m.mu.Unlock()
		return
	}
	m.state = StateStopped
	m.mu.Unlock()

	// Teardown the container via shutdown or terminate, if necessary.
	// For LCOW, this is a no-op as the init process exit will clean up the container too.
	// For WCOW, we need to explicitly shut down the Silo.
	// We do not need to lock this method as this section will only be reached once per container.
	m.teardownContainer(ctx)

	// todo: Release all resources, layers, etc.

	// Always close the container to invalidate any future operations on it.
	if err := m.container.Close(); err != nil {
		log.G(ctx).WithError(err).Error("failed to close container")
	}

	m.mu.Lock()
	m.state = StateTerminated
	close(m.terminatedCh)
	m.mu.Unlock()
}

// Wait blocks until the container has fully terminated (all teardown complete).
//
// It is safe to call Wait concurrently from multiple goroutines; all callers
// will be unblocked simultaneously when the container reaches StateTerminated.
func (m *Manager) Wait(ctx context.Context) {
	ctx, _ = log.WithContext(ctx, logrus.WithFields(logrus.Fields{
		logfields.ContainerID:    m.containerID,
		logfields.GCSContainerID: m.gcsContainerID,
		logfields.Operation:      "Wait Container",
	}))

	select {
	case <-m.terminatedCh:
	case <-ctx.Done():
		log.G(ctx).WithError(ctx.Err()).Error("wait for container to exit failed")
	}
}

func (m *Manager) Update(ctx context.Context, resources interface{}, annotations map[string]string) error {
	ctx, _ = log.WithContext(ctx, logrus.WithFields(logrus.Fields{
		logfields.ContainerID:    m.containerID,
		logfields.GCSContainerID: m.gcsContainerID,
		logfields.Operation:      "Update Container",
	}))

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.state != StateRunning {
		return fmt.Errorf("container %s is in invalid state %s for update: %w", m.ID(), m.state, errdefs.ErrFailedPrecondition)
	}

	return m.updateContainerResources(ctx, resources)
}

func (m *Manager) NewProcess(ctx context.Context, execID string) (*process.Manager, error) {
	ctx, _ = log.WithContext(ctx, logrus.WithFields(logrus.Fields{
		logfields.ContainerID:    m.containerID,
		logfields.GCSContainerID: m.gcsContainerID,
		logfields.Operation:      "New Process",
	}))

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.state != StateRunning {
		return nil, fmt.Errorf("container %s is in invalid state %s for creating new process: %w", m.ID(), m.state, errdefs.ErrFailedPrecondition)
	}

	if _, exists := m.processes[execID]; exists {
		return nil, fmt.Errorf("exec process with ID %q already exists in container %s", execID, m.containerID)
	}
	return process.New(m.containerID, execID, m.container, m.ioRetryTimeout), nil
}

func (m *Manager) GetProcess(execID string) (*process.Manager, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

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
	ctx, _ = log.WithContext(ctx, logrus.WithFields(logrus.Fields{
		logfields.ContainerID:    m.containerID,
		logfields.GCSContainerID: m.gcsContainerID,
		logfields.Operation:      "Pids",
	}))

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
		return nil, fmt.Errorf("failed to fetch container properties: %w", err)
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
	ctx, _ = log.WithContext(ctx, logrus.WithFields(logrus.Fields{
		logfields.ContainerID:    m.containerID,
		logfields.GCSContainerID: m.gcsContainerID,
		logfields.Operation:      "Stats Container",
	}))

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.state != StateRunning {
		return nil, fmt.Errorf("container %s is in invalid state %s for fetching stats: %w", m.ID(), m.state, errdefs.ErrFailedPrecondition)
	}

	s := &stats.Statistics{}
	props, err := m.container.PropertiesV2(ctx, hcsschema.PTStatistics)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch container properties: %w", err)
	}

	if props != nil {
		s.Container = parseContainerStats(props)
	}

	return s, nil
}

func (m *Manager) Delete(ctx context.Context) error {
	//TODO implement me
	// Here we will first check if all the processes are in stopped state.
	// If not we return error. If the processes are in created but not running, we can do cleanup.
	// If all are in stopped state, then we wait for init to exit on its own.
	// then we will call into gm to DeleteContainerState
	panic("implement me")
}
