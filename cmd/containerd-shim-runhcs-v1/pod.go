//go:build windows

package main

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/Microsoft/hcsshim/internal/copyfile"
	"github.com/Microsoft/hcsshim/internal/layers"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/oci"
	"github.com/Microsoft/hcsshim/internal/uvm"
	"github.com/Microsoft/hcsshim/osversion"
	"github.com/Microsoft/hcsshim/pkg/annotations"
	eventstypes "github.com/containerd/containerd/api/events"
	task "github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/containerd/containerd/api/types"
	"github.com/containerd/containerd/v2/core/runtime"
	"github.com/containerd/errdefs"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

// initializeWCOWBootFiles handles the initialization of boot files for WCOW VMs
func initializeWCOWBootFiles(ctx context.Context, wopts *uvm.OptionsWCOW, rootfs []*types.Mount, layerFolders []string) error {
	var (
		err error
	)

	log.G(ctx).WithField("options", log.Format(ctx, *wopts)).Debug("initialize WCOW boot files")

	wopts.BootFiles, err = layers.GetWCOWUVMBootFilesFromLayers(ctx, rootfs, layerFolders)
	if err != nil {
		return err
	}

	if wopts.SecurityPolicyEnabled {
		if wopts.BootFiles.BootType != uvm.BlockCIMBoot {
			return fmt.Errorf("security policy (confidential mode) only works with block CIM based layers")
		}
		// we use measured EFI & rootfs for confidential UVMs, use those instead of the ones passed in layers/rootfs
		wopts.BootFiles.BlockCIMFiles.EFIVHDPath = uvm.GetDefaultConfidentialEFIPath()
		wopts.BootFiles.BlockCIMFiles.BootCIMVHDPath = uvm.GetDefaultConfidentialBootCIMPath()

		// make a copy of the vmgs file as the same vmgs can not be used by multiple pods in parallel
		// TODO(ambarve): for C-LCOW we make a copy in the bundle directory, is it better
		// to use the bundle directory instead of the snapshot directory?
		vmgsCopyPath := filepath.Join(filepath.Dir(wopts.BootFiles.BlockCIMFiles.ScratchVHDPath), filepath.Base(wopts.GuestStateFilePath))
		if err := copyfile.CopyFile(ctx, wopts.GuestStateFilePath, vmgsCopyPath, false); err != nil {
			return fmt.Errorf("failed to make a copy of VMGS: %w", err)
		}
		wopts.GuestStateFilePath = vmgsCopyPath

	} else if wopts.BootFiles.BootType == uvm.BlockCIMBoot {
		// Supporting hyperv isolation with block CIM layers requires changes in
		// the image pull path to prepare the EFI VHD. But more importantly, since both the
		// container and UtilityVM files will be in the same CIM, the early boot
		// code (bootmgr, winload etc.) will need to support reading the UVM OS
		// files from `UtilityVM/Files` inside the CIM. Once that support is added
		// we can enable this.
		return fmt.Errorf("hyperv isolation is not supported with block CIM layers yet")
	}

	// writable EFI VHD is a valid config for both confidential and regular hyperv
	// isolated WCOW. Override the default value here if required.
	if wopts.WritableEFI {
		// Make a copy of EFI VHD, we can't risk the UVM accidentally modifying
		// the original VHD.  make copy next to the scratch VHD, this assumes that
		// the scratch is located in the separate directory dedicated for this
		// UVM.
		writableEFIVHDPath := filepath.Join(filepath.Dir(wopts.BootFiles.BlockCIMFiles.ScratchVHDPath), filepath.Base(wopts.BootFiles.BlockCIMFiles.EFIVHDPath))
		if err := copyfile.CopyFile(ctx, wopts.BootFiles.BlockCIMFiles.EFIVHDPath, writableEFIVHDPath, false); err != nil {
			return fmt.Errorf("failed to copy EFI VHD: %w", err)
		}
		wopts.BootFiles.BlockCIMFiles.EFIVHDPath = writableEFIVHDPath
	}

	return nil
}

// shimPod represents the logical grouping of all tasks in a single set of
// shared namespaces. The pod sandbox (container) is represented by the task
// that matches the `shimPod.ID()`
type shimPod interface {
	// ID is the id of the task representing the pause (sandbox) container.
	ID() string
	// CreateTask creates a workload task within this pod named `tid` with
	// settings `s`.
	//
	// If `tid==ID()` or `tid` is the same as any other task in this pod, this
	// pod MUST return `errdefs.ErrAlreadyExists`.
	CreateTask(ctx context.Context, req *task.CreateTaskRequest, s *specs.Spec) (shimTask, error)
	// GetTask returns a task in this pod that matches `tid`.
	//
	// If `tid` is not found, this pod MUST return `errdefs.ErrNotFound`.
	GetTask(tid string) (shimTask, error)
	// GetTasks returns every task in the pod.
	//
	// If a shim cannot be loaded, this will return an error.
	ListTasks() ([]shimTask, error)
	// KillTask sends `signal` to task that matches `tid`.
	//
	// If `tid` is not found, this pod MUST return `errdefs.ErrNotFound`.
	//
	// If `tid==ID() && eid == "" && all == true` this pod will send `signal` to
	// all tasks in the pod and lastly send `signal` to the sandbox itself.
	//
	// If `all == true && eid != ""` this pod MUST return
	// `errdefs.ErrFailedPrecondition`.
	//
	// A call to `KillTask` is only valid when the exec found by `tid,eid` is in
	// the `shimExecStateRunning, shimExecStateExited` states. If the exec is
	// not in this state this pod MUST return `errdefs.ErrFailedPrecondition`.
	KillTask(ctx context.Context, tid, eid string, signal uint32, all bool) error
	// DeleteTask removes a task from being tracked by this pod, and cleans up
	// the resources the shim allocated for the task.
	//
	// The task's init exec (eid == "") must be either `shimExecStateCreated` or
	// `shimExecStateExited`.  If the exec is not in this state this pod MUST
	// return `errdefs.ErrFailedPrecondition`. Deleting the pod's sandbox task
	// is a no-op.
	DeleteTask(ctx context.Context, tid string) error
}

// validatePodPreconditions checks that the spec `s` is valid to create a pod
// with id `reqID`.
func validatePodPreconditions(reqID string, s *specs.Spec) error {
	if osversion.Build() < osversion.RS5 {
		return errors.Wrapf(errdefs.ErrFailedPrecondition, "pod support is not available on Windows versions previous to RS5 (%d)", osversion.RS5)
	}

	ct, sid, err := oci.GetSandboxTypeAndID(s.Annotations)
	if err != nil {
		return err
	}
	if ct != oci.KubernetesContainerTypeSandbox {
		return errors.Wrapf(
			errdefs.ErrFailedPrecondition,
			"expected annotation: '%s': '%s' got '%s'",
			annotations.KubernetesContainerType,
			oci.KubernetesContainerTypeSandbox,
			ct)
	}
	if sid != reqID {
		return errors.Wrapf(
			errdefs.ErrFailedPrecondition,
			"expected annotation '%s': '%s' got '%s'",
			annotations.KubernetesSandboxID,
			reqID,
			sid)
	}

	if !oci.IsLCOW(s) && !oci.IsWCOW(s) {
		return errors.Wrap(errdefs.ErrFailedPrecondition, "oci spec does not contain WCOW or LCOW spec")
	}

	return nil
}

// createPod is used to create a pod.
func createPod(
	ctx context.Context,
	events publisher,
	req *task.CreateTaskRequest,
	s *specs.Spec,
	parent *uvm.UtilityVM,
	ownsHost bool,
) (_ shimPod, err error) {
	log.G(ctx).WithField("tid", req.ID).Debug("createPod")

	p := pod{
		events: events,
		id:     req.ID,
		spec:   s,
		host:   parent,
	}

	if oci.IsJobContainer(s) {
		// If we're making a job container fake a task (i.e reuse the wcowPodSandbox logic)
		p.sandboxTask = newWcowPodSandboxTask(ctx, events, req.ID, req.Bundle, parent, "", true)
		if err := events.publishEvent(
			ctx,
			runtime.TaskCreateEventTopic,
			&eventstypes.TaskCreate{
				ContainerID: req.ID,
				Bundle:      req.Bundle,
				Rootfs:      req.Rootfs,
				IO: &eventstypes.TaskIO{
					Stdin:    req.Stdin,
					Stdout:   req.Stdout,
					Stderr:   req.Stderr,
					Terminal: req.Terminal,
				},
				Checkpoint: "",
				Pid:        0,
			}); err != nil {
			return nil, err
		}
		p.jobContainer = true
		return &p, nil
	}

	defer func() {
		// clean up the uvm if we fail any further operations
		// and the pod owns the host.
		if err != nil && parent != nil && ownsHost {
			parent.Close()
		}
	}()

	// Set up networking in the UVM if we have one.
	if parent != nil {
		cid := req.ID
		if id, ok := s.Annotations[annotations.NcproxyContainerID]; ok {
			cid = id
		}
		caAddr := fmt.Sprintf(uvm.ComputeAgentAddrFmt, cid)
		if err := parent.CreateAndAssignNetworkSetup(ctx, caAddr, cid); err != nil {
			return nil, err
		}
	}

	// TODO: There is a bug in the compartment activation for Windows
	// Process isolated that requires us to create the real pause container to
	// hold the network compartment open. This is not required for Windows
	// Hypervisor isolated. When we have a build that supports this for Windows
	// Process isolated make sure to move back to this model.

	// For WCOW we fake out the init task since we dont need it. We only
	// need to provision the guest network namespace if this is hypervisor
	// isolated. Process isolated WCOW gets the namespace endpoints
	// automatically.
	if oci.IsIsolated(s) && oci.IsWCOW(s) {
		err = p.setupWCOWPodSandboxTask(ctx, req, s, ownsHost)
		if err != nil {
			return nil, err
		}
	} else {
		// LCOW (and WCOW Process Isolated for the time being) requires a real
		// task for the sandbox.
		lt, err := newHcsTask(ctx, events, parent, ownsHost, req, s, req.ID)
		if err != nil {
			return nil, err
		}
		p.sandboxTask = lt
	}

	return &p, nil
}

var _ = (shimPod)(&pod{})

type pod struct {
	events publisher
	// id is the id of the sandbox task when the pod is created.
	//
	// It MUST be treated as read only in the lifetime of the pod.
	id string
	// sandboxTask is the task that represents the sandbox.
	//
	// Note: The invariant `id==sandboxTask.ID()` MUST be true.
	//
	// It MUST be treated as read only in the lifetime of the pod.
	sandboxTask shimTask
	// host is the UtilityVM that is hosting `sandboxTask` if the task is
	// hypervisor isolated.
	//
	// It MUST be treated as read only in the lifetime of the pod.
	host *uvm.UtilityVM

	// jobContainer specifies whether this pod is for WCOW job containers only.
	//
	// It MUST be treated as read only in the lifetime of the pod.
	jobContainer bool

	// spec is the OCI runtime specification for the pod sandbox container.
	spec *specs.Spec

	workloadTasks sync.Map
}

func (p *pod) ID() string {
	return p.id
}

func (p *pod) CreateTask(ctx context.Context, req *task.CreateTaskRequest, s *specs.Spec) (_ shimTask, err error) {
	if req.ID == p.id {
		return nil, errors.Wrapf(errdefs.ErrAlreadyExists, "task with id: '%s' already exists", req.ID)
	}
	e, _ := p.sandboxTask.GetExec("")
	if e.State() != shimExecStateRunning {
		return nil, errors.Wrapf(errdefs.ErrFailedPrecondition, "task with id: '%s' cannot be created in pod: '%s' which is not running", req.ID, p.id)
	}

	_, ok := p.workloadTasks.Load(req.ID)
	if ok {
		return nil, errors.Wrapf(errdefs.ErrAlreadyExists, "task with id: '%s' already exists id pod: '%s'", req.ID, p.id)
	}

	if p.jobContainer {
		// This is a short circuit to make sure that all containers in a pod will have
		// the same IP address/be added to the same compartment.
		//
		// There will need to be OS work needed to support this scenario, so for now we need to block on
		// this.
		if !oci.IsJobContainer(s) {
			return nil, errors.New("cannot create a normal process isolated container if the pod sandbox is a job container")
		}
		// Pass through some annotations from the pod spec that if specified will need to be made available
		// to every container as well. Kubernetes only passes annotations to RunPodSandbox so there needs to be
		// a way for individual containers to get access to these.
		oci.SandboxAnnotationsPassThrough(
			p.spec.Annotations,
			s.Annotations,
			annotations.HostProcessInheritUser,
			annotations.HostProcessRootfsLocation,
		)
	}

	ct, sid, err := oci.GetSandboxTypeAndID(s.Annotations)
	if err != nil {
		return nil, err
	}
	if ct != oci.KubernetesContainerTypeContainer {
		return nil, errors.Wrapf(
			errdefs.ErrFailedPrecondition,
			"expected annotation: '%s': '%s' got '%s'",
			annotations.KubernetesContainerType,
			oci.KubernetesContainerTypeContainer,
			ct)
	}
	if sid != p.id {
		return nil, errors.Wrapf(
			errdefs.ErrFailedPrecondition,
			"expected annotation '%s': '%s' got '%s'",
			annotations.KubernetesSandboxID,
			p.id,
			sid)
	}

	st, err := newHcsTask(ctx, p.events, p.host, false, req, s, p.id)
	if err != nil {
		return nil, err
	}

	p.workloadTasks.Store(req.ID, st)
	return st, nil
}

func (p *pod) GetTask(tid string) (shimTask, error) {
	if tid == p.id {
		return p.sandboxTask, nil
	}
	raw, loaded := p.workloadTasks.Load(tid)
	if !loaded {
		return nil, errors.Wrapf(errdefs.ErrNotFound, "task with id: '%s' not found", tid)
	}
	return raw.(shimTask), nil
}

func (p *pod) ListTasks() (_ []shimTask, err error) {
	tasks := []shimTask{p.sandboxTask}
	p.workloadTasks.Range(func(key, value interface{}) bool {
		wt, loaded := value.(shimTask)
		if !loaded {
			err = fmt.Errorf("failed to load tasks %s", key)
			return false
		}
		tasks = append(tasks, wt)
		// Iterate all. Returning false stops the iteration. See:
		// https://pkg.go.dev/sync#Map.Range
		return true
	})
	if err != nil {
		return nil, err
	}
	return tasks, nil
}

func (p *pod) KillTask(ctx context.Context, tid, eid string, signal uint32, all bool) error {
	t, err := p.GetTask(tid)
	if err != nil {
		return err
	}
	if all && eid != "" {
		return errors.Wrapf(errdefs.ErrFailedPrecondition, "cannot signal all with non empty ExecID: '%s'", eid)
	}
	eg := errgroup.Group{}
	if all && tid == p.id {
		// We are in a kill all on the sandbox task. Signal everything.
		p.workloadTasks.Range(func(key, value interface{}) bool {
			wt := value.(shimTask)
			eg.Go(func() error {
				return wt.KillExec(ctx, eid, signal, all)
			})

			// Iterate all. Returning false stops the iteration. See:
			// https://pkg.go.dev/sync#Map.Range
			return true
		})
	}
	eg.Go(func() error {
		return t.KillExec(ctx, eid, signal, all)
	})
	return eg.Wait()
}

func (p *pod) DeleteTask(ctx context.Context, tid string) error {
	// Deleting the sandbox task is a no-op, since the service should delete its
	// reference to the sandbox task or pod, and `p.sandboxTask != nil` is an
	// invariant that is relied on elsewhere.
	// However, still get the init exec for all tasks to ensure that they have
	// been properly stopped.

	t, err := p.GetTask(tid)
	if err != nil {
		return errors.Wrap(err, "could not find task to delete")
	}

	e, err := t.GetExec("")
	if err != nil {
		return errors.Wrap(err, "could not get initial exec")
	}
	if e.State() == shimExecStateRunning {
		return errors.Wrap(errdefs.ErrFailedPrecondition, "cannot delete task with running exec")
	}

	if p.id != tid {
		p.workloadTasks.Delete(tid)
	}

	return nil
}

func (p *pod) setupWCOWPodSandboxTask(
	ctx context.Context,
	req *task.CreateTaskRequest,
	s *specs.Spec,
	ownsHost bool,
) error {
	nsId := ""

	if s.Windows.Network != nil && s.Windows.Network.NetworkNamespace != "" {
		if err := p.host.ConfigureNetworking(
			ctx,
			s.Windows.Network.NetworkNamespace,
		); err != nil {
			return errors.Wrapf(err, "failed to setup networking for pod %q", req.ID)
		}
		nsId = s.Windows.Network.NetworkNamespace
	}

	p.sandboxTask = newWcowPodSandboxTask(
		ctx,
		p.events,
		req.ID,
		req.Bundle,
		p.host,
		nsId,
		ownsHost)
	// Publish the created event. We only do this for a fake WCOW task. A
	// HCS Task will event itself based on actual process lifetime.
	if err := p.events.publishEvent(
		ctx,
		runtime.TaskCreateEventTopic,
		&eventstypes.TaskCreate{
			ContainerID: req.ID,
			Bundle:      req.Bundle,
			Rootfs:      req.Rootfs,
			IO: &eventstypes.TaskIO{
				Stdin:    req.Stdin,
				Stdout:   req.Stdout,
				Stderr:   req.Stderr,
				Terminal: req.Terminal,
			},
			Checkpoint: "",
			Pid:        0,
		}); err != nil {
		return err
	}

	return nil
}
