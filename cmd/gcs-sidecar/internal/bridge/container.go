package bridge

import (
	"context"
	"fmt"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"sync"

	"github.com/Microsoft/hcsshim/internal/cow"
	"github.com/Microsoft/hcsshim/internal/jobcontainers"
	oci "github.com/opencontainers/runtime-spec/specs-go"
)

type Container struct {
	id          string
	spec        *oci.Spec
	container   cow.Container
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

func (c *Container) CreateProcess(ctx context.Context, params *hcsschema.ProcessParameters) (cow.Process, error) {
	p, err := c.container.CreateProcess(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to create process: %w", err)
	}

	c.processesMutex.Lock()
	c.processes[uint32(p.Pid())] = p
	c.processesMutex.Unlock()

	return p, nil
}

func (c *Container) GetProcess(pid uint32) (cow.Process, error) {
	c.processesMutex.Lock()
	defer c.processesMutex.Unlock()

	if p, ok := c.processes[pid]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("process with pid %d not found", pid)
}
