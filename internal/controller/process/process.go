//go:build windows

package process

import (
	"context"
	"fmt"
	"time"

	"github.com/Microsoft/hcsshim/internal/cmd"
	"github.com/Microsoft/hcsshim/internal/cow"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/containerd/containerd/api/runtime/task/v3"
	"github.com/containerd/errdefs"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

type Manager struct {
	containerID string

	// execID is the unique identifier for this exec instance.
	execID string

	process cow.Process

	hostingSystem cow.ProcessHost

	status Status

	bundle string

	processID int

	upstreamIO cmd.UpstreamIO

	processSpecs *specs.Process
}

var _ Controller = (*Manager)(nil)

func New(containerID string, execID string, hostingSystem cow.ProcessHost) *Manager {
	return &Manager{
		containerID:   containerID,
		execID:        execID,
		hostingSystem: hostingSystem,
		status:        StatusUnknown,
	}
}

func (m *Manager) Create(ctx context.Context, opts *CreateOptions) error {
	upstreamIO, err := cmd.NewUpstreamIO(ctx, m.containerID, opts.Stdout, opts.Stderr, opts.Stdin, opts.Terminal, opts.IoRetryTimeoutInSec)
	if err != nil {
		return fmt.Errorf("failed to create upstream IO: %w", err)
	}

	m.upstreamIO = upstreamIO
	m.bundle = opts.Bundle
	m.processSpecs = opts.Spec
	m.status = StatusCreated

	return nil
}

func (m *Manager) Pid() int {
	return m.processID
}

func (m *Manager) Start(ctx context.Context) (int, error) {
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
		// todo: in calling code check for equivalent condition- he.isWCOW || he.id != he.tid
		Spec: m.processSpecs, // caller needs to ensure that this is actually needed.
	}

	if err := command.Start(); err != nil {
		return 0, err
	}

	m.process = command.Process

	m.processID = m.process.Pid()

	// todo: send task exec start event.
	// or move these events to the service layer.

	// todo: wait for exit code equivalent
	// here we call m.process.Wait()

	m.status = StatusRunning
	return m.processID, nil
}

func (m *Manager) Status(verbose bool) *task.StateResponse {
	resp := &task.StateResponse{
		ID:     m.containerID,
		ExecID: m.execID,
		Pid:    uint32(m.processID),
		Status: 0, // todo: set the correct status
	}

	if !verbose {
		return resp
	}

	// todo: figure out the status, exit code and exit time.

	resp.Bundle = m.bundle
	resp.Stdin = m.upstreamIO.StdinPath()
	resp.Stdout = m.upstreamIO.StdoutPath()
	resp.Stderr = m.upstreamIO.StderrPath()
	resp.Terminal = m.upstreamIO.Terminal()
	resp.ExitStatus = 0 // todo: set the correct exit code
	resp.ExitedAt = nil // todo: set the correct exit time

	return resp
}

func (m *Manager) ResizeConsole(ctx context.Context, width, height uint32) error {
	if m.status != StatusRunning {
		// todo: in old shim, we made this a no-op instead of returning error.
		return fmt.Errorf("cannot resize console for exec that is not running")
	}

	if !m.upstreamIO.Terminal() {
		return fmt.Errorf("exec: '%s' in task: '%s' is not a tty: %w", m.execID, m.containerID, errdefs.ErrFailedPrecondition)
	}

	return m.process.ResizeConsole(ctx, uint16(width), uint16(height))
}

func (m *Manager) CloseIO(ctx context.Context) {
	m.upstreamIO.CloseStdin(ctx)
}
