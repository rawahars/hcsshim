package bridge

import (
	"context"
	"fmt"
	"github.com/Microsoft/go-winio"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"io"
	"log"
	"sync"

	"github.com/Microsoft/hcsshim/internal/cow"
	"github.com/Microsoft/hcsshim/internal/jobcontainers"
	oci "github.com/opencontainers/runtime-spec/specs-go"
)

type Container struct {
	id        string
	spec      *oci.Spec
	container cow.Container

	initDoOnce  sync.Once
	initProcess cow.Process

	processesMutex sync.Mutex
	processes      map[uint32]cow.Process
}

func NewContainer(id string, spec *oci.Spec) (*Container, error) {
	opts := jobcontainers.CreateOptions{WCOWLayers: nil}
	container, _, err := jobcontainers.Create(
		context.Background(),
		id,
		spec,
		opts,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create job container: %w", err)
	}

	return &Container{
		id:        id,
		spec:      spec,
		container: container,
		processes: make(map[uint32]cow.Process),
	}, nil
}

func (c *Container) ID() string {
	return c.id
}

func (c *Container) Start(ctx context.Context) error {
	return c.container.Start(ctx)
}

func (c *Container) Modify(ctx context.Context, config interface{}) error {
	return c.container.Modify(ctx, config)
}

func (c *Container) Shutdown(ctx context.Context) error {
	return c.container.Shutdown(ctx)
}

func (c *Container) Terminate(ctx context.Context) error {
	return c.container.Terminate(ctx)
}

func (c *Container) Wait() error {
	return c.container.Wait()
}

func (c *Container) CreateProcess(
	ctx context.Context,
	params *hcsschema.ProcessParameters,
	stdioConfig *executeProcessStdioRelaySettings,
) (cow.Process, error) {
	p, err := c.container.CreateProcess(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to create process: %w", err)
	}

	// Assign the first process made as the init process of the container.
	c.initDoOnce.Do(func() {
		c.initProcess = p
	})

	// Start relaying process IO.
	log.Printf("Creating stdio connection with hvsockets from host: %+v", stdioConfig)
	stdin, stdout, stderr := p.Stdio()
	if params.CreateStdInPipe {
		go func() {
			addr := &winio.HvsockAddr{
				VMID:      winio.HvsockGUIDParent(),
				ServiceID: *stdioConfig.StdIn,
			}
			conn, err := winio.Dial(ctx, addr)
			if err != nil {
				log.Printf("failed to connect to stdin pipe: %v", err)
				return
			}

			_, err = io.Copy(stdin, conn)
			if err != nil {
				log.Printf("failed to copy stdin pipe: %v", err)
			}

			// Notify the process that there is no more input.
			if err := p.CloseStdin(context.TODO()); err != nil {
				log.Printf("failed to close stdin pipe: %v", err)
				return
			}
		}()
	}

	if params.CreateStdOutPipe {
		go func() {
			addr := &winio.HvsockAddr{
				VMID:      winio.HvsockGUIDParent(),
				ServiceID: *stdioConfig.StdOut,
			}
			conn, err := winio.Dial(ctx, addr)
			if err != nil {
				log.Printf("failed to connect to stdout pipe: %v", err)
				return
			}

			_, err = io.Copy(conn, stdout)
			if err != nil {
				log.Printf("failed to copy stdout pipe: %v", err)
			}

			// Notify the process that there is no more input.
			if err := p.CloseStdout(context.TODO()); err != nil {
				log.Printf("failed to close stdout pipe: %v", err)
				return
			}
		}()
	}

	if params.CreateStdErrPipe {
		go func() {
			addr := &winio.HvsockAddr{
				VMID:      winio.HvsockGUIDParent(),
				ServiceID: *stdioConfig.StdErr,
			}
			conn, err := winio.Dial(ctx, addr)
			if err != nil {
				log.Printf("failed to connect to stderr pipe: %v", err)
				return
			}

			_, err = io.Copy(conn, stderr)
			if err != nil {
				log.Printf("failed to copy stderr pipe: %v", err)
			}

			// Notify the process that there is no more input.
			if err := p.CloseStderr(context.TODO()); err != nil {
				log.Printf("failed to close stderr pipe: %v", err)
				return
			}
		}()
	}

	c.processesMutex.Lock()
	c.processes[uint32(p.Pid())] = p
	c.processesMutex.Unlock()

	return p, nil
}

func (c *Container) RemoveProcessState(pid uint32) {
	c.processesMutex.Lock()
	defer c.processesMutex.Unlock()
	delete(c.processes, pid)
}

func (c *Container) GetProcess(pid uint32) (cow.Process, error) {
	c.processesMutex.Lock()
	defer c.processesMutex.Unlock()

	if p, ok := c.processes[pid]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("process with pid %d not found", pid)
}
