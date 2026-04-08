//go:build windows

package process

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Microsoft/hcsshim/internal/cmd"
	"github.com/Microsoft/hcsshim/internal/cow"
	"github.com/Microsoft/hcsshim/internal/hcs"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/logfields"

	eventstypes "github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/containerd/errdefs"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type CreateOptions struct {
	Bundle string

	Spec *specs.Process

	Terminal bool

	Stdin string

	Stdout string

	Stderr string
}

type Controller struct {
	mu          sync.Mutex
	containerID string

	// execID is the unique identifier for this exec instance.
	execID string

	process cow.Process

	hostingSystem cow.ProcessHost

	state State

	bundle string

	processID int

	IoRetryTimeoutInSec time.Duration

	upstreamIO cmd.UpstreamIO

	processSpecs *specs.Process

	exitedAt time.Time

	exitCode uint32

	// exitedCh is closed when the process has exited and all cleanup is done.
	exitedCh chan struct{}
}

func New(containerID string, execID string, hostingSystem cow.ProcessHost, IoRetryTimeoutInSec time.Duration) *Controller {
	return &Controller{
		containerID:         containerID,
		execID:              execID,
		hostingSystem:       hostingSystem,
		state:               StateNotCreated,
		IoRetryTimeoutInSec: IoRetryTimeoutInSec,
		exitCode:            255, // By design for non-exited process status.
		exitedCh:            make(chan struct{}),
	}
}

// todo: check state transitions.
// todo: Created to Exit

func (c *Controller) Pid() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.processID
}

func (c *Controller) Create(ctx context.Context, opts *CreateOptions) error {
	ctx, _ = log.WithContext(ctx, logrus.WithField(logfields.Operation, "Create Process"))

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != StateNotCreated {
		return fmt.Errorf("invalid state transition: process is already created")
	}

	if opts.Terminal && opts.Stderr != "" {
		return fmt.Errorf("if using terminal, stderr must be empty: %w", errdefs.ErrFailedPrecondition)
	}

	upstreamIO, err := cmd.NewUpstreamIO(ctx, c.containerID, opts.Stdout, opts.Stderr, opts.Stdin, opts.Terminal, c.IoRetryTimeoutInSec)
	if err != nil {
		return fmt.Errorf("failed to create upstream IO: %w", err)
	}

	c.upstreamIO = upstreamIO
	c.bundle = opts.Bundle
	c.processSpecs = opts.Spec
	c.state = StateCreated

	return nil
}

func (c *Controller) Start(ctx context.Context, sendEvent func(interface{})) (int, error) {
	ctx, _ = log.WithContext(ctx, logrus.WithField(logfields.Operation, "Start Process"))

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != StateCreated {
		return -1, fmt.Errorf("invalid state transition: process is not in created state")
	}

	command := &cmd.Cmd{
		Host:   c.hostingSystem,
		Stdin:  c.upstreamIO.Stdin(),
		Stdout: c.upstreamIO.Stdout(),
		Stderr: c.upstreamIO.Stderr(),
		Log: log.G(ctx).WithFields(logrus.Fields{
			"containerID": c.containerID,
			"execID":      c.execID,
		}),
		CopyAfterExitTimeout: time.Second * 1,
		// An init exec passes the process as part of the config. We only pass
		// the spec if this is a true exec.
		Spec: c.processSpecs, // caller needs to ensure that this is actually needed.
	}

	if err := command.Start(); err != nil {
		return 0, err
	}

	c.process = command.Process

	c.processID = c.process.Pid()

	go c.handleProcessExit(ctx, command, sendEvent)

	c.state = StateRunning
	return c.processID, nil
}

// handleProcessExit blocks until the process exits, cleans up IO, and publishes the exit event via sendEvent.
func (c *Controller) handleProcessExit(ctx context.Context, gcsCmd *cmd.Cmd, sendEvent func(interface{})) {
	// Detach from the caller's context so upstream cancellation/timeout does
	// not abort the background teardown.
	ctx = context.WithoutCancel(ctx)

	// Wrap all the errors we encounter.
	var err error

	// Wait for the process to exit.
	err = c.process.Wait()
	if err != nil {
		log.G(ctx).WithError(err).Error("process wait failed")
	}

	c.mu.Lock()
	if c.state == StateTerminated {
		// todo: check for invalid state and other states.
		log.G(ctx).Warnf("process %s is already in terminated state", c.execID)
		c.mu.Unlock()
		return
	}

	c.state = StateTerminated
	c.mu.Unlock()

	code, err := c.process.ExitCode()
	if err != nil {
		log.G(ctx).WithError(err).Error("failed to get ExitCode")
	} else {
		log.G(ctx).WithField("exitCode", code).Debug("exited")
	}

	c.exitCode = uint32(code)
	c.exitedAt = time.Now()

	// Wait for all IO copies to complete and free the resources.
	_ = gcsCmd.Wait()
	c.upstreamIO.Close(ctx)

	close(c.exitedCh)

	// Publish the exit event after all cleanup is done.
	if sendEvent != nil {
		status := c.Status(true)
		sendEvent(&eventstypes.TaskExit{
			ContainerID: c.containerID,
			ID:          status.ExecID,
			Pid:         status.Pid,
			ExitStatus:  status.ExitStatus,
			ExitedAt:    status.ExitedAt,
		})
	}
}

func (c *Controller) Status(verbose bool) *task.StateResponse {
	c.mu.Lock()
	defer c.mu.Unlock()

	resp := &task.StateResponse{
		ID:     c.containerID,
		ExecID: c.execID,
		Pid:    uint32(c.processID),
		Status: c.state.ContainerdStatus(),
	}

	if verbose {
		resp.Bundle = c.bundle
		resp.Stdin = c.upstreamIO.StdinPath()
		resp.Stdout = c.upstreamIO.StdoutPath()
		resp.Stderr = c.upstreamIO.StderrPath()
		resp.Terminal = c.upstreamIO.Terminal()
		resp.ExitStatus = c.exitCode
		resp.ExitedAt = timestamppb.New(c.exitedAt)
	}

	return resp
}

func (c *Controller) State() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

func (c *Controller) ResizeConsole(ctx context.Context, width, height uint32) error {
	ctx, _ = log.WithContext(ctx, logrus.WithField(logfields.Operation, "ResizeConsole"))

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != StateRunning {
		return fmt.Errorf("cannot resize console for exec that is not running")
	}

	if !c.upstreamIO.Terminal() {
		return fmt.Errorf("exec: '%s' in task: '%s' is not a tty: %w", c.execID, c.containerID, errdefs.ErrFailedPrecondition)
	}

	return c.process.ResizeConsole(ctx, uint16(width), uint16(height))
}

func (c *Controller) CloseIO(ctx context.Context) {
	ctx, _ = log.WithContext(ctx, logrus.WithField(logfields.Operation, "CloseIO"))

	// If we have any upstream IO we close the upstream connection. This will
	// unblock the `io.Copy` in the `Start()` call which will signal
	// `cmd.CloseStdin()`. This is safe to call multiple times.
	c.upstreamIO.CloseStdin(ctx)
}

func (c *Controller) Wait(ctx context.Context) {
	select {
	case <-c.exitedCh:
	case <-ctx.Done():
	}
}

// Kill delivers a signal to the process or terminates it.
// signalOptions contains the platform-specific signal options (e.g.,
// SignalProcessOptionsWCOW or SignalProcessOptionsLCOW). The caller is
// responsible for validating the signal and producing the correct options
// for the platform. When signalOptions is nil the Kill (terminate)
// path is used instead.
func (c *Controller) Kill(ctx context.Context, signalOptions interface{}) error {
	ctx, _ = log.WithContext(ctx, logrus.WithField(logfields.Operation, "Kill Process"))

	c.mu.Lock()
	state := c.state
	c.mu.Unlock()

	switch state {
	case StateCreated:
		// The process was never started. Abort handles the full teardown.
		return c.Abort(ctx, 1)
	case StateRunning:
		var delivered bool
		var err error

		if signalOptions != nil {
			delivered, err = c.process.Signal(ctx, signalOptions)
		} else {
			// Legacy path: signals are not supported, issue a direct terminate.
			delivered, err = c.process.Kill(ctx)
		}

		if err != nil {
			if hcs.IsAlreadyStopped(err) {
				// Desired state is actual state. No need to error just because
				// the process is already dead.
				return nil
			}
			return err
		}
		if !delivered {
			return fmt.Errorf("exec %q in task %q not found: %w", c.execID, c.containerID, errdefs.ErrNotFound)
		}
		return nil
	case StateTerminated:
		return fmt.Errorf("exec %q in task %q not found: %w", c.execID, c.containerID, errdefs.ErrNotFound)
	default:
		return fmt.Errorf("kill process %s: invalid state %s", c.execID, state)
	}
}

// Abort transitions a created-but-never-started process to terminated state and releases its IO resources.
func (c *Controller) Abort(ctx context.Context, exitCode int) error {
	ctx, _ = log.WithContext(ctx, logrus.WithField(logfields.Operation, "Abort Process"))

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != StateCreated {
		return fmt.Errorf("abort process %s: invalid state %s, expected %s", c.execID, c.state, StateCreated)
	}

	// The process was never started, so there is no OS-level process to
	// signal. Transition directly to terminated and release all resources.
	c.state = StateTerminated
	c.exitCode = uint32(exitCode)
	c.exitedAt = time.Now()

	// Release upstream IO connections that were never used in a copy.
	c.upstreamIO.Close(ctx)

	// Unblock any waiters.
	close(c.exitedCh)

	return nil
}
