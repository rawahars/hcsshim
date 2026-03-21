//go:build windows

package process

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Microsoft/hcsshim/internal/cmd"
	"github.com/Microsoft/hcsshim/internal/cow"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/logfields"
	"github.com/containerd/containerd/api/runtime/task/v3"
	"github.com/containerd/errdefs"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Manager struct {
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

var _ Controller = (*Manager)(nil)

func New(containerID string, execID string, hostingSystem cow.ProcessHost, IoRetryTimeoutInSec time.Duration) *Manager {
	return &Manager{
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

func (m *Manager) Pid() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.processID
}

func (m *Manager) Create(ctx context.Context, opts *CreateOptions) error {
	ctx, _ = log.WithContext(ctx, logrus.WithField(logfields.Operation, "Create Process"))

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.state != StateNotCreated {
		return fmt.Errorf("invalid state transition: process is already created")
	}

	if opts.Terminal && opts.Stderr != "" {
		return fmt.Errorf("if using terminal, stderr must be empty: %w", errdefs.ErrFailedPrecondition)
	}

	upstreamIO, err := cmd.NewUpstreamIO(ctx, m.containerID, opts.Stdout, opts.Stderr, opts.Stdin, opts.Terminal, m.IoRetryTimeoutInSec)
	if err != nil {
		return fmt.Errorf("failed to create upstream IO: %w", err)
	}

	m.upstreamIO = upstreamIO
	m.bundle = opts.Bundle
	m.processSpecs = opts.Spec
	m.state = StateCreated

	return nil
}

func (m *Manager) Start(ctx context.Context) (int, error) {
	ctx, _ = log.WithContext(ctx, logrus.WithField(logfields.Operation, "Start Process"))

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.state != StateCreated {
		return -1, fmt.Errorf("invalid state transition: process is not in created state")
	}

	command := &cmd.Cmd{
		Host:   m.hostingSystem,
		Stdin:  m.upstreamIO.Stdin(),
		Stdout: m.upstreamIO.Stdout(),
		Stderr: m.upstreamIO.Stderr(),
		Log: log.G(ctx).WithFields(logrus.Fields{
			"containerID": m.containerID,
			"execID":      m.execID,
		}),
		CopyAfterExitTimeout: time.Second * 1,
		// An init exec passes the process as part of the config. We only pass
		// the spec if this is a true exec.
		Spec: m.processSpecs, // caller needs to ensure that this is actually needed.
	}

	if err := command.Start(); err != nil {
		return 0, err
	}

	m.process = command.Process

	m.processID = m.process.Pid()

	go m.handleProcessExit(ctx, command)

	m.state = StateRunning
	return m.processID, nil
}

func (m *Manager) handleProcessExit(ctx context.Context, gcsCmd *cmd.Cmd) {
	// Detach from the caller's context so upstream cancellation/timeout does
	// not abort the background teardown.
	ctx = context.WithoutCancel(ctx)

	// Wrap all the errors we encounter.
	var err error

	// Wait for the process to exit.
	err = m.process.Wait()
	if err != nil {
		log.G(ctx).WithError(err).Error("process wait failed")
	}

	m.mu.Lock()
	if m.state == StateTerminated {
		// todo: check for invalid state and other states.
		log.G(ctx).Warnf("process %s is already in terminated state", m.execID)
		m.mu.Unlock()
		return
	}

	m.state = StateTerminated
	m.mu.Unlock()

	code, err := m.process.ExitCode()
	if err != nil {
		log.G(ctx).WithError(err).Error("failed to get ExitCode")
	} else {
		log.G(ctx).WithField("exitCode", code).Debug("exited")
	}

	m.exitCode = uint32(code)
	m.exitedAt = time.Now()

	// Wait for all IO copies to complete and free the resources.
	_ = gcsCmd.Wait()
	m.upstreamIO.Close(ctx)

	close(m.exitedCh)
}

func (m *Manager) Status(verbose bool) *task.StateResponse {
	m.mu.Lock()
	defer m.mu.Unlock()

	resp := &task.StateResponse{
		ID:     m.containerID,
		ExecID: m.execID,
		Pid:    uint32(m.processID),
		Status: m.state.ContainerdStatus(),
	}

	if verbose {
		resp.Bundle = m.bundle
		resp.Stdin = m.upstreamIO.StdinPath()
		resp.Stdout = m.upstreamIO.StdoutPath()
		resp.Stderr = m.upstreamIO.StderrPath()
		resp.Terminal = m.upstreamIO.Terminal()
		resp.ExitStatus = m.exitCode
		resp.ExitedAt = timestamppb.New(m.exitedAt)
	}

	return resp
}

func (m *Manager) ResizeConsole(ctx context.Context, width, height uint32) error {
	ctx, _ = log.WithContext(ctx, logrus.WithField(logfields.Operation, "ResizeConsole"))

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.state != StateRunning {
		return fmt.Errorf("cannot resize console for exec that is not running")
	}

	if !m.upstreamIO.Terminal() {
		return fmt.Errorf("exec: '%s' in task: '%s' is not a tty: %w", m.execID, m.containerID, errdefs.ErrFailedPrecondition)
	}

	return m.process.ResizeConsole(ctx, uint16(width), uint16(height))
}

func (m *Manager) CloseIO(ctx context.Context) {
	ctx, _ = log.WithContext(ctx, logrus.WithField(logfields.Operation, "CloseIO"))

	// If we have any upstream IO we close the upstream connection. This will
	// unblock the `io.Copy` in the `Start()` call which will signal
	// `cmd.CloseStdin()`. This is safe to call multiple times.
	m.upstreamIO.CloseStdin(ctx)
}

func (m *Manager) Wait(ctx context.Context) {
	select {
	case <-m.exitedCh:
	case <-ctx.Done():
	}
}
