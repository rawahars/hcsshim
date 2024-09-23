package linuxvm

import (
	"context"

	"github.com/Microsoft/hcsshim/internal/cmd"
	"github.com/Microsoft/hcsshim/internal/core"
	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
)

type process struct {
	cmd     *cmd.Cmd
	io      cmd.UpstreamIO
	waitCh  chan struct{}
	waitErr error
}

func newProcess(cmd *cmd.Cmd, io cmd.UpstreamIO) *process {
	return &process{
		cmd:    cmd,
		io:     io,
		waitCh: make(chan struct{}),
	}
}

func (p *process) Start(ctx context.Context) error {
	if err := p.cmd.Start(); err != nil {
		return err
	}
	go p.waitBackground()
	return nil
}

func (p *process) Wait(ctx context.Context) error {
	select {
	case <-p.waitCh:
		return p.waitErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *process) waitBackground() {
	p.waitErr = p.cmd.Wait()
	p.io.Close(context.Background())
	close(p.waitCh)
}

func (p *process) Status() core.Status {
	var status status
	select {
	case <-p.waitCh:
		status.exited = true
		status.code = p.cmd.ExitState.ExitCode()
	default:
	}
	return status
}

func (p *process) Pid() int {
	return p.cmd.Process.Pid()
}

func (p *process) CloseIO(ctx context.Context) {
	p.io.CloseStdin(ctx)
}

func (p *process) Signal(ctx context.Context, signal int) error {
	_, err := p.cmd.Process.Signal(ctx, &guestresource.SignalProcessOptionsLCOW{Signal: signal})
	return err
}
