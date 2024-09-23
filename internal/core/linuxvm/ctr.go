package linuxvm

import (
	"context"

	"github.com/Microsoft/hcsshim/internal/cmd"
	"github.com/Microsoft/hcsshim/internal/core"
	"github.com/Microsoft/hcsshim/internal/cow"
	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
	"github.com/opencontainers/runtime-spec/specs-go"
)

type ctr struct {
	innerCtr cow.Container
	init     *process
	io       cmd.UpstreamIO
	waitCh   chan struct{}
	waitErr  error
}

var _ core.Ctr = (*ctr)(nil)

func newCtr(innerCtr cow.Container, processSpec *specs.Process, io cmd.UpstreamIO) *ctr {
	cmd := &cmd.Cmd{
		Host: innerCtr,
		Spec: processSpec,
	}
	if io != nil {
		cmd.Stdin = io.Stdin()
		cmd.Stdout = io.Stdout()
		cmd.Stderr = io.Stderr()
	}
	ctr := &ctr{
		innerCtr: innerCtr,
		init:     newProcess(cmd, io),
		waitCh:   make(chan struct{}),
	}
	return ctr
}

func (c *ctr) Start(ctx context.Context) error {
	if err := c.innerCtr.Start(ctx); err != nil {
		return err
	}
	if err := c.init.Start(ctx); err != nil {
		return err
	}
	go c.waitBackground()
	return nil
}

func (c *ctr) Wait(ctx context.Context) error {
	select {
	case <-c.waitCh:
		return c.waitErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *ctr) waitBackground() {
	c.waitErr = func() error {
		if err := c.init.Wait(context.Background()); err != nil {
			return err
		}
		<-c.innerCtr.WaitChannel()
		return c.innerCtr.WaitError()
	}()
	if c.io != nil {
		c.io.Close(context.Background())
	}
	close(c.waitCh)
}

func (c *ctr) Status() core.Status {
	var status status
	select {
	case <-c.waitCh:
		status.exited = true
		status.code = c.init.cmd.ExitState.ExitCode()
	default:
	}
	return status
}

type status struct {
	exited bool
	code   int
}

func (s status) Exited() bool {
	return s.exited
}

func (s status) ExitCode() int {
	return s.code
}

func (c *ctr) Pid() int {
	return c.init.cmd.Process.Pid()
}

func (c *ctr) CreateProcess(ctx context.Context, config *core.ProcessConfig) (core.Process, error) {
	cmd := &cmd.Cmd{
		Host: c.innerCtr,
		Spec: config.Spec,
	}
	if config.IO != nil {
		cmd.Stdin = config.IO.Stdin()
		cmd.Stdout = config.IO.Stdout()
		cmd.Stderr = config.IO.Stderr()
	}
	return newProcess(cmd, config.IO), nil
}

func (c *ctr) CloseIO(ctx context.Context) {
	if c.io != nil {
		c.io.CloseStdin(ctx)
	}
}

func (c *ctr) Signal(ctx context.Context, signal int) error {
	_, err := c.init.cmd.Process.Signal(ctx, &guestresource.SignalProcessOptionsLCOW{Signal: signal})
	return err
}
