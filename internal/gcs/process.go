//go:build windows

package gcs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/hcsshim/internal/cow"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/logfields"
	"github.com/Microsoft/hcsshim/internal/oc"
	statepkg "github.com/Microsoft/hcsshim/internal/state"
	"github.com/sirupsen/logrus"
	"go.opencensus.io/trace"
)

const (
	hrNotFound = 0x80070490
)

// Process represents a process in a container or container host.
type Process struct {
	gc                                *GuestConnection
	cid                               string
	id                                uint32
	waitCall                          *rpc
	waitResp                          containerWaitForProcessResponse
	stdin, stdout, stderr             Conn
	stdinCloseWriteOnce               sync.Once
	stdinCloseWriteErr                error
	stdinPort, stdoutPort, stderrPort uint32
}

var _ cow.Process = &Process{}

type baseProcessParams struct {
	CreateStdInPipe, CreateStdOutPipe, CreateStdErrPipe bool
}

func (gc *GuestConnection) exec(ctx context.Context, cid string, params interface{}) (_ cow.Process, err error) {
	pid, err := gc.execInner(ctx, cid, params)
	if err != nil {
		return nil, err
	}
	p, err := gc.OpenProcess(ctx, cid, pid)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (gc *GuestConnection) execInner(ctx context.Context, cid string, params interface{}) (pid uint32, err error) {
	b, err := json.Marshal(params)
	if err != nil {
		return 0, err
	}
	var bp baseProcessParams
	err = json.Unmarshal(b, &bp)
	if err != nil {
		return 0, err
	}

	req := containerExecuteProcess{
		requestBase: makeRequest(ctx, cid),
		Settings: executeProcessSettings{
			ProcessParameters: anyInString{params},
		},
	}

	p := &Process{gc: gc, cid: cid}
	defer func() {
		if err != nil {
			p.Close()
		}
	}()

	// Construct the stdio channels. Windows guests expect hvsock service IDs
	// instead of vsock ports.
	var hvsockSettings executeProcessStdioRelaySettings
	var vsockSettings executeProcessVsockStdioRelaySettings
	if gc.os == "windows" {
		req.Settings.StdioRelaySettings = &hvsockSettings
	} else {
		req.Settings.VsockStdioRelaySettings = &vsockSettings
	}
	if bp.CreateStdInPipe {
		p.stdin, vsockSettings.StdIn, err = gc.newIoChannel()
		if err != nil {
			return 0, err
		}
		g := winio.VsockServiceID(vsockSettings.StdIn)
		hvsockSettings.StdIn = &g
	}
	if bp.CreateStdOutPipe {
		p.stdout, vsockSettings.StdOut, err = gc.newIoChannel()
		if err != nil {
			return 0, err
		}
		g := winio.VsockServiceID(vsockSettings.StdOut)
		hvsockSettings.StdOut = &g
	}
	if bp.CreateStdErrPipe {
		p.stderr, vsockSettings.StdErr, err = gc.newIoChannel()
		if err != nil {
			return 0, err
		}
		g := winio.VsockServiceID(vsockSettings.StdErr)
		hvsockSettings.StdErr = &g
	}
	p.stdinPort, p.stdoutPort, p.stderrPort = vsockSettings.StdIn, vsockSettings.StdOut, vsockSettings.StdErr

	var resp containerExecuteProcessResponse
	err = gc.brdg.RPC(ctx, rpcExecuteProcess, &req, &resp, false)
	if err != nil {
		return 0, err
	}
	p.id = resp.ProcessID
	gc.mu.Lock()
	defer gc.mu.Unlock()
	gc.procs[procIdent{cid, p.id}] = p
	log.G(ctx).WithField("pid", p.id).Debug("created process pid")
	return p.id, nil
}

func (gc *GuestConnection) OpenProcess(ctx context.Context, cid string, pid uint32) (_ cow.Process, err error) {
	gc.mu.Lock()
	defer gc.mu.Unlock()
	p := gc.procs[procIdent{cid, pid}]
	// Start a wait message.
	waitReq := containerWaitForProcess{
		requestBase: makeRequest(ctx, cid),
		ProcessID:   p.id,
		TimeoutInMs: 0xffffffff,
	}
	p.waitCall, err = gc.brdg.AsyncRPC(ctx, rpcWaitForProcess, &waitReq, &p.waitResp)
	if err != nil {
		return nil, fmt.Errorf("failed to wait on process, leaking process: %s", err)
	}
	go p.waitBackground()
	return p, nil
}

type processState struct {
	CID                               string
	PID                               uint32
	StdinPort, StdoutPort, StderrPort uint32
}

func (p *Process) Save(ctx context.Context, path string) error {
	if err := os.MkdirAll(path, 0755); err != nil {
		return err
	}
	s := processState{
		CID:        p.cid,
		PID:        p.id,
		StdinPort:  p.stdinPort,
		StdoutPort: p.stdoutPort,
		StderrPort: p.stderrPort,
	}
	if err := statepkg.Write(filepath.Join(path, "state.json"), &s); err != nil {
		return err
	}
	return nil
}

// Close releases resources associated with the process and closes the
// associated standard IO streams.
func (p *Process) Close() error {
	ctx, span := oc.StartSpan(context.Background(), "gcs::Process::Close")
	defer span.End()
	span.AddAttributes(
		trace.StringAttribute("cid", p.cid),
		trace.Int64Attribute("pid", int64(p.id)))

	if p.stdin != nil {
		if err := p.stdin.Close(); err != nil {
			log.G(ctx).WithError(err).Warn("close stdin failed")
		}
	}
	if p.stdout != nil {
		if err := p.stdout.Close(); err != nil {
			log.G(ctx).WithError(err).Warn("close stdout failed")
		}
	}
	if p.stderr != nil {
		if err := p.stderr.Close(); err != nil {
			log.G(ctx).WithError(err).Warn("close stderr failed")
		}
	}
	p.gc.mu.Lock()
	defer p.gc.mu.Unlock()
	delete(p.gc.procs, procIdent{p.cid, p.id})
	return nil
}

// CloseStdin causes the process to read EOF on its stdin stream.
func (p *Process) CloseStdin(ctx context.Context) (err error) {
	ctx, span := oc.StartSpan(ctx, "gcs::Process::CloseStdin") //nolint:ineffassign,staticcheck
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()
	span.AddAttributes(
		trace.StringAttribute("cid", p.cid),
		trace.Int64Attribute("pid", int64(p.id)))

	p.stdinCloseWriteOnce.Do(func() {
		p.stdinCloseWriteErr = p.stdin.CloseWrite()
	})
	return p.stdinCloseWriteErr
}

func (p *Process) CloseStdout(ctx context.Context) (err error) {
	ctx, span := oc.StartSpan(ctx, "gcs::Process::CloseStdout") //nolint:ineffassign,staticcheck
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()
	span.AddAttributes(
		trace.StringAttribute("cid", p.cid),
		trace.Int64Attribute("pid", int64(p.id)))

	return p.stdout.Close()
}

func (p *Process) CloseStderr(ctx context.Context) (err error) {
	ctx, span := oc.StartSpan(ctx, "gcs::Process::CloseStderr") //nolint:ineffassign,staticcheck
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()
	span.AddAttributes(
		trace.StringAttribute("cid", p.cid),
		trace.Int64Attribute("pid", int64(p.id)))

	return p.stderr.Close()
}

// ExitCode returns the process's exit code, or an error if the process is still
// running or the exit code is otherwise unknown.
func (p *Process) ExitCode() (_ int, err error) {
	if !p.waitCall.Done() {
		return -1, errors.New("process not exited")
	}
	if err := p.waitCall.Err(); err != nil {
		return -1, err
	}
	return int(p.waitResp.ExitCode), nil
}

// Kill sends a forceful terminate signal to the process and returns whether the
// signal was delivered. The process might not be terminated by the time this
// returns.
func (p *Process) Kill(ctx context.Context) (_ bool, err error) {
	ctx, span := oc.StartSpan(ctx, "gcs::Process::Kill")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()
	span.AddAttributes(
		trace.StringAttribute("cid", p.cid),
		trace.Int64Attribute("pid", int64(p.id)))

	return p.Signal(ctx, nil)
}

// Pid returns the process ID.
func (p *Process) Pid() int {
	return int(p.id)
}

// ResizeConsole requests that the pty associated with the process resize its
// window.
func (p *Process) ResizeConsole(ctx context.Context, width, height uint16) (err error) {
	ctx, span := oc.StartSpan(ctx, "gcs::Process::ResizeConsole", oc.WithClientSpanKind)
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()
	span.AddAttributes(
		trace.StringAttribute("cid", p.cid),
		trace.Int64Attribute("pid", int64(p.id)))

	req := containerResizeConsole{
		requestBase: makeRequest(ctx, p.cid),
		ProcessID:   p.id,
		Height:      height,
		Width:       width,
	}
	var resp responseBase
	return p.gc.brdg.RPC(ctx, rpcResizeConsole, &req, &resp, true)
}

// Signal sends a signal to the process, returning whether it was delivered.
func (p *Process) Signal(ctx context.Context, options interface{}) (_ bool, err error) {
	ctx, span := oc.StartSpan(ctx, "gcs::Process::Signal", oc.WithClientSpanKind)
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()
	span.AddAttributes(
		trace.StringAttribute("cid", p.cid),
		trace.Int64Attribute("pid", int64(p.id)))

	req := containerSignalProcess{
		requestBase: makeRequest(ctx, p.cid),
		ProcessID:   p.id,
		Options:     options,
	}
	var resp responseBase
	// FUTURE: SIGKILL is idempotent and can safely be cancelled, but this interface
	//		   does currently make it easy to determine what signal is being sent.
	err = p.gc.brdg.RPC(ctx, rpcSignalProcess, &req, &resp, false)
	if err != nil {
		if uint32(resp.Result) != hrNotFound {
			return false, err
		}
		if !p.waitCall.Done() {
			log.G(ctx).WithFields(logrus.Fields{
				logrus.ErrorKey:       err,
				logfields.ContainerID: p.cid,
				logfields.ProcessID:   p.id,
			}).Warn("ignoring missing process")
		}
		return false, nil
	}
	return true, nil
}

// Stdio returns the standard IO streams associated with the container. They
// will be closed when Close is called.
func (p *Process) Stdio() (stdin io.Writer, stdout, stderr io.Reader) {
	return p.stdin, p.stdout, p.stderr
}

// Wait waits for the process (or guest connection) to terminate.
func (p *Process) Wait() error {
	p.waitCall.Wait()
	return p.waitCall.Err()
}

func (p *Process) waitBackground() {
	ctx, span := oc.StartSpan(context.Background(), "gcs::Process::waitBackground")
	defer span.End()
	span.AddAttributes(
		trace.StringAttribute("cid", p.cid),
		trace.Int64Attribute("pid", int64(p.id)))

	p.waitCall.Wait()
	ec, err := p.ExitCode()
	if err != nil {
		log.G(ctx).WithError(err).Error("failed wait")
	}
	log.G(ctx).WithField("exitCode", ec).Debug("process exited")
	oc.SetSpanStatus(span, err)
}
