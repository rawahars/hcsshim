//go:build windows && lcow

package pod

import (
	"context"
	"fmt"
	"sort"

	"github.com/Microsoft/hcsshim/internal/controller/linuxcontainer"
	"github.com/Microsoft/hcsshim/internal/controller/network"
	podsave "github.com/Microsoft/hcsshim/internal/controller/pod/save"
	"github.com/containerd/containerd/api/runtime/task/v2"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// Save returns the pod controller's migration payload as an [anypb.Any]
// tagged with [podsave.TypeURL]. The returned envelope captures the
// pod identifiers and carries the network controller's and each container
// controller's [anypb.Any] envelopes opaquely. Containers are emitted in
// deterministic (sorted) order to keep snapshot diffs stable.
func (c *Controller) Save(ctx context.Context) (*anypb.Any, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Sort container IDs first so the emitted children are deterministically
	// ordered — useful for diffing snapshots and for stable test output.
	ids := make([]string, 0, len(c.containers))
	for id := range c.containers {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	containers := make([]*anypb.Any, 0, len(ids))
	for _, id := range ids {
		cs, err := c.containers[id].Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("save container %q: %w", id, err)
		}
		containers = append(containers, cs)
	}

	state := &podsave.Payload{
		PodID:      c.podID,
		GcsPodID:   c.gcsPodID,
		Containers: containers,
	}

	if c.network != nil {
		ns, err := c.network.Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("save network controller: %w", err)
		}
		state.Network = ns
	}

	payload, err := proto.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("marshal pod saved state for %q: %w", c.podID, err)
	}
	return &anypb.Any{TypeUrl: podsave.TypeURL, Value: payload}, nil
}

// Import rehydrates a [Controller] from a [Controller.Save]'d envelope
// without binding any host/guest interfaces. Static state and the network
// controller are restored; container rehydration is deferred until the
// linuxcontainer package gains its own Import/Resume APIs. The returned
// controller is inert until [Controller.Resume] supplies the live VM.
func Import(env *anypb.Any) (*Controller, error) {
	if env == nil {
		return nil, fmt.Errorf("pod saved-state envelope is nil")
	}
	if env.GetTypeUrl() != podsave.TypeURL {
		return nil, fmt.Errorf("unsupported pod saved-state type %q", env.GetTypeUrl())
	}

	state := &podsave.Payload{}
	if err := proto.Unmarshal(env.GetValue(), state); err != nil {
		return nil, fmt.Errorf("unmarshal pod saved state: %w", err)
	}
	if v := state.GetSchemaVersion(); v != podsave.SchemaVersion {
		return nil, fmt.Errorf("unsupported pod saved-state schema version %d (want %d)", v, podsave.SchemaVersion)
	}

	netCtrl, err := network.Import(state.GetNetwork())
	if err != nil {
		return nil, fmt.Errorf("import network controller: %w", err)
	}

	c := &Controller{
		podID:      state.GetPodID(),
		gcsPodID:   state.GetGcsPodID(),
		containers: make(map[string]*linuxcontainer.Controller, len(state.GetContainers())),
		network:    netCtrl,
	}

	for _, cAny := range state.GetContainers() {
		cc, err := linuxcontainer.Import(cAny)
		if err != nil {
			return nil, fmt.Errorf("import container in pod %q: %w", c.podID, err)
		}
		c.containers[cc.ContainerID()] = cc
	}

	return c, nil
}

// Resume binds the live VM to a controller previously produced by [Import]
// and resumes its embedded network controller, transitioning it into
// nextNetState. Must be called once the destination VM is running before any
// pod-level operation is invoked.
func (c *Controller) Resume(vm vmController, nextNetState network.State) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.vm = vm
	// In production c.network is always *network.Controller (set by [New] or
	// [Import]); the interface field exists only to keep the operational
	// surface mockable.
	// todo: FIX THIS BEFORE SHIPPING.
	if net, ok := c.network.(*network.Controller); ok {
		// Mirrors the dependency wiring in [vm.Controller.NetworkController]:
		// the UtilityVM provides the host-side NIC manager while the Guest
		// implements both guest-side NIC injection and capability lookup.
		guest := vm.Guest()
		net.Resume(nextNetState, vm.VM(), guest, guest)
	}
}

func (c *Controller) Patch(
	ctx context.Context,
	sourceContainerID string,
	request *task.CreateTaskRequest,
	isSandbox bool,
) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	cc, ok := c.containers[sourceContainerID]
	if !ok {
		return fmt.Errorf("container %q not found in pod %q", sourceContainerID, c.podID)
	}
	if sourceContainerID != request.ID {
		if _, exists := c.containers[request.ID]; exists {
			return fmt.Errorf("container %q already exists in pod %q", request.ID, c.podID)
		}
	}

	if err := cc.Patch(ctx, request); err != nil {
		return fmt.Errorf("patch container %q: %w", sourceContainerID, err)
	}

	if sourceContainerID != request.ID {
		delete(c.containers, sourceContainerID)
		c.containers[request.ID] = cc
	}
	if isSandbox {
		c.podID = request.ID
	}
	return nil
}
