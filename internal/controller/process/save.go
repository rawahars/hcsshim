//go:build windows && (lcow || wcow)

package process

import (
	"context"
	"encoding/json"
	"fmt"

	procsave "github.com/Microsoft/hcsshim/internal/controller/process/save"
	"github.com/Microsoft/hcsshim/internal/cow"

	"github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Save returns the process controller's migration payload as an [anypb.Any]
// tagged with [procsave.TypeURL]. The returned envelope captures the
// lifecycle stage, IO vsock ports, and the original OCI process spec needed
// to rebind the process on the destination.
func (c *Controller) Save(_ context.Context) (*anypb.Any, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	state := &procsave.Payload{
		ExecID:         c.execID,
		State:          procsave.Stage(c.state),
		Pid:            int32(c.processID),
		Bundle:         c.bundle,
		ExitedAt:       timestamppb.New(c.exitedAt),
		ExitCode:       c.exitCode,
		IoRetryTimeout: durationpb.New(c.ioRetryTimeout),
	}
	if c.process != nil {
		state.StdinPort, state.StdoutPort, state.StderrPort = c.process.IOPorts()
	}
	if c.processSpec != nil {
		raw, err := json.Marshal(c.processSpec)
		if err != nil {
			return nil, fmt.Errorf("marshal process spec for %q/%q: %w", c.containerID, c.execID, err)
		}
		state.OciProcessSpecJson = raw
	}

	payload, err := proto.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("marshal process saved state for %q/%q: %w", c.containerID, c.execID, err)
	}
	return &anypb.Any{TypeUrl: procsave.TypeURL, Value: payload}, nil
}

// Import rehydrates a [Controller] from a [Controller.Save]'d envelope
// without binding any host-side handles. The returned controller is placed
// in [StateMigrating] so all operational APIs reject calls until
// [Controller.Resume] supplies the live hosting system / process handle
// and the next state.
func Import(env *anypb.Any, containerID string) (*Controller, error) {
	if env == nil {
		return nil, fmt.Errorf("process saved-state envelope is nil")
	}
	if env.GetTypeUrl() != procsave.TypeURL {
		return nil, fmt.Errorf("unsupported process saved-state type %q", env.GetTypeUrl())
	}

	state := &procsave.Payload{}
	if err := proto.Unmarshal(env.GetValue(), state); err != nil {
		return nil, fmt.Errorf("unmarshal process saved state: %w", err)
	}
	if v := state.GetSchemaVersion(); v != procsave.SchemaVersion {
		return nil, fmt.Errorf("unsupported process saved-state schema version %d (want %d)", v, procsave.SchemaVersion)
	}

	// todo: we need to take care of Upstream IO
	c := &Controller{
		containerID:    containerID,
		execID:         state.GetExecID(),
		ioRetryTimeout: state.GetIoRetryTimeout().AsDuration(),
		state:          StateMigrating,
		processID:      int(state.GetPid()),
		bundle:         state.GetBundle(),
		exitedAt:       state.GetExitedAt().AsTime(),
		exitCode:       state.GetExitCode(),
		exitedCh:       make(chan struct{}),
	}

	if raw := state.GetOciProcessSpecJson(); len(raw) > 0 {
		spec := &specs.Process{}
		if err := json.Unmarshal(raw, spec); err != nil {
			return nil, fmt.Errorf("unmarshal process spec for %q/%q: %w", c.containerID, c.execID, err)
		}
		c.processSpec = spec
	}

	return c, nil
}

// Resume binds the live hosting system and (optional) process handle to a
// controller previously produced by [Import] and transitions it from
// [StateMigrating] into next. If next is [StateTerminated], any caller
// blocked on [Controller.Wait] is unblocked.
func (c *Controller) Resume(next State, hostingSystem cow.ProcessHost, process cow.Process) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.hostingSystem = hostingSystem
	c.process = process
	c.state = next

	if next == StateTerminated {
		close(c.exitedCh)
	}
}
