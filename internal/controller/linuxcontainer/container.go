//go:build windows && lcow

package linuxcontainer

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	runhcsopts "github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/options"
	"github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/stats"
	"github.com/Microsoft/hcsshim/internal/controller/process"
	"github.com/Microsoft/hcsshim/internal/gcs"
	"github.com/Microsoft/hcsshim/internal/hcs/schema1"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/logfields"
	"github.com/Microsoft/hcsshim/internal/oci"
	"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
	"github.com/Microsoft/hcsshim/internal/signals"
	"github.com/Microsoft/hcsshim/internal/vm/vmutils"

	"github.com/Microsoft/go-winio/pkg/guid"
	eventstypes "github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/api/runtime/task/v2"
	containerdtypes "github.com/containerd/containerd/api/types/task"
	"github.com/containerd/errdefs"
	"github.com/containerd/typeurl/v2"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Controller is the concrete implementation of Controller.
// It is the leaf node of the component hierarchy: it holds OCI-derived specs,
// drives the device controllers, and communicates with the GCS via guestmanager.
type Controller struct {
	mu sync.RWMutex

	vmID string

	gcsPodID string

	// containerID is the unique identifier for this container.
	// This is provided by containerd.
	containerID string

	// gcsContainerID is the identifier for the container used
	// while interacting with GCS.
	gcsContainerID string

	// guestMgr is used to create and manage the GCS container entity.
	guestMgr guest

	scsi scsiController

	plan9 plan9Controller

	vpci vPCIController

	// Host-side resource reservations released during teardown.
	layers         *scsiLayers
	scsiResources  []guid.GUID
	plan9Resources []guid.GUID
	devices        []guid.GUID

	container *gcs.Container

	state State

	// terminatedCh is closed exactly once when the container reaches
	// StateTerminated. All callers of Wait block on this channel, and
	// closing it unblocks every waiter simultaneously — the standard
	// Go broadcast pattern.
	terminatedCh chan struct{}

	// processes maps exec IDs to their process controllers.
	// The init process is stored with exec ID "".
	processes map[string]*process.Controller

	ioRetryTimeout time.Duration
}

// New creates a ready-to-use Controller.
func New(
	vmID string,
	gcsPodID string,
	containerID string,
	guestMgr guest,
	scsiCtrl scsiController,
	plan9Ctrl plan9Controller,
	vpci vPCIController,
) *Controller {
	return &Controller{
		vmID:        vmID,
		gcsPodID:    gcsPodID,
		containerID: containerID,
		// Same id is used as the container. GCS is tightly coupled with original ID.
		// Post migration, we can always change the primary ID while gcs used the original ID.
		gcsContainerID: containerID,
		guestMgr:       guestMgr,
		scsi:           scsiCtrl,
		plan9:          plan9Ctrl,
		vpci:           vpci,
		processes:      make(map[string]*process.Controller),
		state:          StateNotCreated,
		terminatedCh:   make(chan struct{}),
	}
}

func (c *Controller) ID() string {
	return c.containerID
}

func (c *Controller) Create(ctx context.Context, spec *specs.Spec, opts *task.CreateTaskRequest, copts *CreateContainerOpts) (err error) {
	ctx, _ = log.WithContext(ctx, logrus.WithField(logfields.GCSContainerID, c.gcsContainerID))
	log.G(ctx).WithField(logfields.ContainerID, c.containerID).Debug("creating container")

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != StateNotCreated {
		return fmt.Errorf("container %s is in invalid state %s for create: %w", c.ID(), c.state, errdefs.ErrFailedPrecondition)
	}

	// Parse the runtime options from the request.
	shimOpts, err := vmutils.UnmarshalRuntimeOptions(ctx, opts.Options)
	if err != nil {
		return fmt.Errorf("unmarshal runtime options: %w", err)
	}

	// Apply any updates to the OCI spec based on the shim options.
	*spec = oci.UpdateSpecFromOptions(*spec, shimOpts)

	// Expand annotations after defaults have been loaded in from options.
	// Since annotation expansion is used to toggle security features,
	// raise the error rather than suppress and move on.
	if err = oci.ProcessAnnotations(ctx, spec.Annotations); err != nil {
		return fmt.Errorf("process OCI spec annotations: %w", err)
	}

	// Upon any failure from this point onwards, we want to perform a teardown
	// of container resources.
	defer func() {
		if err != nil {
			c.releaseResources(ctx)
		}
	}()

	// Allocate all host-side resources and build the GCS container document.
	gcsDocument, err := c.generateContainerDocument(ctx, spec, opts.Rootfs, copts.IsScratchEncryptionEnabled)
	if err != nil {
		return fmt.Errorf("generate container document: %w", err)
	}

	// Create the container within UVM.
	c.container, err = c.guestMgr.CreateContainer(ctx, c.gcsContainerID, gcsDocument)
	if err != nil {
		return fmt.Errorf("create container in guest: %w", err)
	}

	// Default to an infinite timeout (zero value).
	if shimOpts != nil {
		c.ioRetryTimeout = time.Duration(shimOpts.IoRetryTimeoutInSec) * time.Second
	}

	// Create the initial process controller with exec ID "".
	initProcess := process.New(c.containerID, "", c.container, c.ioRetryTimeout)
	if err = initProcess.Create(ctx, &process.CreateOptions{
		Bundle:   opts.Bundle,
		Terminal: opts.Terminal,
		Stdin:    opts.Stdin,
		Stdout:   opts.Stdout,
		Stderr:   opts.Stderr,
	}); err != nil {
		if closeErr := c.container.Close(); closeErr != nil {
			log.G(ctx).WithError(closeErr).Error("failed to close container during cleanup")
		}
		return fmt.Errorf("create init process: %w", err)
	}
	c.processes[""] = initProcess

	c.state = StateCreated

	return nil
}

// releaseResources undoes each allocation in reverse order.
// It is idempotent — subsequent calls after the first are no-ops.
// Errors are logged but do not stop the remaining cleanup.
func (c *Controller) releaseResources(ctx context.Context) {
	// Combined layers must be removed before unmapping the underlying SCSI
	// layer devices — the guest overlay filesystem references those devices.
	if c.layers != nil && c.layers.layersCombined {
		var hcsLayers []hcsschema.Layer
		for _, layer := range c.layers.roLayers {
			hcsLayers = append(hcsLayers, hcsschema.Layer{Path: layer.guestPath})
		}

		if err := c.guestMgr.RemoveLCOWCombinedLayers(ctx, guestresource.LCOWCombinedLayers{
			ContainerID:       c.gcsContainerID,
			ContainerRootPath: c.layers.rootfsPath,
			Layers:            hcsLayers,
			ScratchPath:       c.layers.scratch.guestPath,
		}); err != nil {
			log.G(ctx).WithError(err).Error("failed to remove combined layers from guest")
		}
	}

	// Unmap layers (scratch + RO layers).
	if c.layers != nil {
		if err := c.scsi.UnmapFromGuest(ctx, c.layers.scratch.id); err != nil {
			log.G(ctx).WithError(err).Error("failed to unmap scratch layer")
		}

		for _, layer := range c.layers.roLayers {
			if err := c.scsi.UnmapFromGuest(ctx, layer.id); err != nil {
				log.G(ctx).WithError(err).Error("failed to unmap ro layer")
			}
		}
	}

	// Unmap additional SCSI mounts.
	for _, id := range c.scsiResources {
		if err := c.scsi.UnmapFromGuest(ctx, id); err != nil {
			log.G(ctx).WithError(err).Error("failed to unmap scsi resource")
		}
	}

	// Unmap Plan9 shares.
	for _, id := range c.plan9Resources {
		if err := c.plan9.UnmapFromGuest(ctx, id); err != nil {
			log.G(ctx).WithError(err).Error("failed to unmap plan9 share")
		}
	}

	// Remove VPCI devices.
	for _, id := range c.devices {
		if err := c.vpci.RemoveFromVM(ctx, id); err != nil {
			log.G(ctx).WithError(err).Error("failed to remove vpci device")
		}
	}

	// Clear all resource references so a repeated call is a no-op, and the
	// GC can reclaim the slices.
	c.layers = nil
	c.scsiResources = nil
	c.plan9Resources = nil
	c.devices = nil
}

func (c *Controller) Start(ctx context.Context, notifCallback func(interface{})) (uint32, error) {
	ctx, _ = log.WithContext(ctx, logrus.WithFields(logrus.Fields{
		logfields.ContainerID:    c.containerID,
		logfields.GCSContainerID: c.gcsContainerID,
		logfields.Operation:      "Start Container",
	}))

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != StateCreated {
		return 1, fmt.Errorf("container %s is in invalid state %s for start: %w", c.ID(), c.state, errdefs.ErrFailedPrecondition)
	}

	// Start the container.
	err := c.container.Start(ctx)
	if err != nil {
		c.state = StateInvalid
		return 1, fmt.Errorf("start container %s: %w", c.ID(), err)
	}

	// Get the init process and call start on the same.
	// Pass nil for sendEvent because the init process exit event is published
	// by handleInitProcessExit after full container teardown.
	pid, err := c.processes[""].Start(ctx, nil)
	if err != nil {
		c.state = StateInvalid
		return 1, fmt.Errorf("start init process: %w", err)
	}

	c.state = StateRunning

	go c.handleInitProcessExit(ctx, c.processes[""], notifCallback)

	return uint32(pid), nil
}

// handleInitProcessExit blocks until the init process exits, then tears down
// the container, marks it terminated, and publishes the exit event via sendEvent.
// Must be run as a goroutine.
func (c *Controller) handleInitProcessExit(ctx context.Context, initProcess *process.Controller, notifCallback func(interface{})) {
	// Detach from the caller's context so upstream cancellation/timeout does
	// not abort the background teardown.
	ctx = context.WithoutCancel(ctx)

	// Block until the init process exits.
	initProcess.Wait(ctx)

	c.mu.Lock()
	if c.state != StateRunning {
		log.G(ctx).Warn("unexpected container state during init process exit handling")
		c.mu.Unlock()
		return
	}
	c.state = StateStopped
	c.mu.Unlock()

	// Release all resource allocations made during Create.
	c.releaseResources(ctx)

	// Always close the container to invalidate any future operations on it.
	if err := c.container.Close(); err != nil {
		log.G(ctx).WithError(err).Error("failed to close container")
	}

	c.mu.Lock()
	c.state = StateTerminated
	close(c.terminatedCh)
	c.mu.Unlock()

	// Publish the exit event for the init process after teardown is complete.
	if notifCallback != nil {
		status := initProcess.Status(true)
		notifCallback(&eventstypes.TaskExit{
			ContainerID: c.containerID,
			ID:          status.ExecID,
			Pid:         status.Pid,
			ExitStatus:  status.ExitStatus,
			ExitedAt:    status.ExitedAt,
		})
	}
}

// Wait blocks until the container has fully terminated (all teardown complete).
//
// It is safe to call Wait concurrently from multiple goroutines; all callers
// will be unblocked simultaneously when the container reaches StateTerminated.
func (c *Controller) Wait(ctx context.Context) {
	ctx, _ = log.WithContext(ctx, logrus.WithFields(logrus.Fields{
		logfields.ContainerID:    c.containerID,
		logfields.GCSContainerID: c.gcsContainerID,
		logfields.Operation:      "Wait Container",
	}))

	select {
	case <-c.terminatedCh:
	case <-ctx.Done():
		log.G(ctx).WithError(ctx.Err()).Error("wait for container to exit failed")
	}
}

func (c *Controller) Update(ctx context.Context, resources interface{}) error {
	ctx, _ = log.WithContext(ctx, logrus.WithFields(logrus.Fields{
		logfields.ContainerID:    c.containerID,
		logfields.GCSContainerID: c.gcsContainerID,
		logfields.Operation:      "Update Container",
	}))

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != StateRunning {
		return fmt.Errorf("container %s is in invalid state %s for update: %w", c.ID(), c.state, errdefs.ErrFailedPrecondition)
	}

	linuxRes, ok := resources.(*specs.LinuxResources)
	if !ok {
		return errors.New("container resources must be of type *specs.LinuxResources")
	}

	return c.container.Modify(ctx, guestrequest.ModificationRequest{
		ResourceType: guestresource.ResourceTypeContainerConstraints,
		RequestType:  guestrequest.RequestTypeUpdate,
		Settings: guestresource.LCOWContainerConstraints{
			Linux: *linuxRes,
		},
	})
}

func (c *Controller) NewProcess(ctx context.Context, execID string) (*process.Controller, error) {
	ctx, _ = log.WithContext(ctx, logrus.WithFields(logrus.Fields{
		logfields.ContainerID:    c.containerID,
		logfields.GCSContainerID: c.gcsContainerID,
		logfields.Operation:      "New Process",
	}))

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != StateRunning {
		return nil, fmt.Errorf("container %s is in invalid state %s for creating new process: %w", c.ID(), c.state, errdefs.ErrFailedPrecondition)
	}

	if _, exists := c.processes[execID]; exists {
		return nil, fmt.Errorf("exec process with ID %q already exists in container %s", execID, c.containerID)
	}

	newProcess := process.New(c.containerID, execID, c.container, c.ioRetryTimeout)
	c.processes[execID] = newProcess

	return newProcess, nil
}

func (c *Controller) GetProcess(execID string) (*process.Controller, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	p, ok := c.processes[execID]
	if !ok {
		return nil, fmt.Errorf("process with exec ID %s not found", execID)
	}
	return p, nil
}

func (c *Controller) ListProcesses() (map[string]*process.Controller, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make(map[string]*process.Controller, len(c.processes))
	for id, p := range c.processes {
		result[id] = p
	}
	return result, nil
}

func (c *Controller) Pids(ctx context.Context) ([]*containerdtypes.ProcessInfo, error) {
	ctx, _ = log.WithContext(ctx, logrus.WithFields(logrus.Fields{
		logfields.ContainerID:    c.containerID,
		logfields.GCSContainerID: c.gcsContainerID,
		logfields.Operation:      "Pids",
	}))

	c.mu.RLock()
	defer c.mu.RUnlock()

	// Map all tracked exec's to pid/exec-id
	pidMap := make(map[int]string)
	for execID, p := range c.processes {
		pidMap[p.Pid()] = execID
	}

	// Get the guest pids
	props, err := c.container.Properties(ctx, schema1.PropertyTypeProcessList)
	if err != nil {
		return nil, fmt.Errorf("fetch container properties: %w", err)
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
			return nil, fmt.Errorf("marshal process details for exec %s in container %s: %w", pd.ExecID, c.containerID, err)
		}
		processes[i] = &containerdtypes.ProcessInfo{
			Pid:  pd.ProcessID,
			Info: typeurl.MarshalProto(a),
		}
	}
	return processes, nil
}

func (c *Controller) Stats(ctx context.Context) (*stats.Statistics, error) {
	ctx, _ = log.WithContext(ctx, logrus.WithFields(logrus.Fields{
		logfields.ContainerID:    c.containerID,
		logfields.GCSContainerID: c.gcsContainerID,
		logfields.Operation:      "Stats Container",
	}))

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.state != StateRunning {
		return nil, fmt.Errorf("container %s is in invalid state %s for fetching stats: %w", c.ID(), c.state, errdefs.ErrFailedPrecondition)
	}

	s := &stats.Statistics{}
	props, err := c.container.PropertiesV2(ctx, hcsschema.PTStatistics)
	if err != nil {
		return nil, fmt.Errorf("fetch container properties: %w", err)
	}

	if props != nil {
		s.Container = &stats.Statistics_Linux{Linux: props.Metrics}
	}

	return s, nil
}

// KillProcess delivers a signal to the specified process or all processes in the container.
func (c *Controller) KillProcess(ctx context.Context, execID string, signal uint32, all bool) error {
	ctx, _ = log.WithContext(ctx, logrus.WithFields(logrus.Fields{
		logfields.ContainerID:    c.containerID,
		logfields.GCSContainerID: c.gcsContainerID,
		logfields.Operation:      "KillProcess",
	}))

	if all && execID != "" {
		return fmt.Errorf("cannot signal all for non-empty exec %q: %w", execID, errdefs.ErrFailedPrecondition)
	}

	signalsSupported := c.guestMgr.Capabilities().IsSignalProcessSupported()
	signalOptions, err := signals.ValidateLCOW(int(signal), signalsSupported)
	if err != nil {
		return fmt.Errorf("validate signal %d for container %s: %w", signal, c.containerID, err)
	}

	// When "all" is requested, deliver the signal to every additional exec
	// in the container on a best-effort basis. Errors are logged but do not
	// prevent the target process from being signaled.
	if all {
		c.mu.Lock()
		for eid, proc := range c.processes {
			if eid == execID {
				// Skip the target — it is signaled below.
				continue
			}
			if killErr := proc.Kill(ctx, signalOptions); killErr != nil {
				log.G(ctx).WithFields(logrus.Fields{
					"execID":        eid,
					logrus.ErrorKey: killErr,
				}).Warn("failed to kill exec in container")
			}
		}
		c.mu.Unlock()
	}

	// Signal the target process.
	targetProcess, err := c.GetProcess(execID)
	if err != nil {
		return fmt.Errorf("get process %q in container %s: %w", execID, c.containerID, err)
	}

	return targetProcess.Kill(ctx, signalOptions)
}

// DeleteProcess removes the process identified by execID from the container and returns its last status.
func (c *Controller) DeleteProcess(ctx context.Context, execID string) (*task.StateResponse, error) {
	ctx, _ = log.WithContext(ctx, logrus.WithFields(logrus.Fields{
		logfields.ContainerID:    c.containerID,
		logfields.GCSContainerID: c.gcsContainerID,
		logfields.Operation:      "DeleteProcess",
	}))

	c.mu.Lock()
	defer c.mu.Unlock()

	proc, ok := c.processes[execID]
	if !ok {
		return nil, fmt.Errorf("process with exec ID %q not found in container %s", execID, c.containerID)
	}

	procState := proc.State()

	// A running process must be explicitly killed before it can be deleted.
	if procState == process.StateRunning {
		return nil, fmt.Errorf("cannot delete process %q in container %s while it is running: %w", execID, c.containerID, errdefs.ErrFailedPrecondition)
	}

	// If the process was created but never started, abort it to release IO
	// resources and unblock any waiters.
	if procState == process.StateCreated {
		if err := proc.Abort(ctx, 1); err != nil {
			return nil, fmt.Errorf("abort created process %q in container %s: %w", execID, c.containerID, err)
		}
	}

	// Capture the process status before removing the entry.
	status := proc.Status(true)

	// Deleting the init process (execID "") means the container itself is
	// being torn down.
	if execID == "" && c.guestMgr.Capabilities().IsDeleteContainerStateSupported() {
		if err := c.guestMgr.DeleteContainerState(ctx, c.gcsContainerID); err != nil {
			return nil, fmt.Errorf("delete container state for %s: %w", c.gcsContainerID, err)
		}
	}

	// Remove the process entry only after all fallible operations have
	// succeeded, so that a retry can still locate the process.
	delete(c.processes, execID)

	return status, nil
}
