//go:build windows && (lcow || wcow)

package vpci

import (
	"context"
	"fmt"

	"github.com/Microsoft/go-winio/pkg/guid"
	vpcisave "github.com/Microsoft/hcsshim/internal/controller/device/vpci/save"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// Save returns the VPCI sub-controller's migration payload as an
// [anypb.Any] tagged with [vpcisave.TypeURL]. The returned envelope
// enumerates every assigned device keyed by its VMBus instance GUID, along
// with its lifecycle stage and outstanding reference count.
func (c *Controller) Save(_ context.Context) (*anypb.Any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	state := &vpcisave.Payload{
		SchemaVersion: vpcisave.SchemaVersion,
		Devices:       make(map[string]*vpcisave.DeviceState, len(c.devices)),
	}
	for vmBusGUID, info := range c.devices {
		state.Devices[vmBusGUID.String()] = &vpcisave.DeviceState{
			DeviceInstanceID:     info.device.DeviceInstanceID,
			VirtualFunctionIndex: uint32(info.device.VirtualFunctionIndex),
			State:                vpcisave.DeviceStage(info.state),
			RefCount:             info.refCount,
		}
	}

	payload, err := proto.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("marshal vpci saved state: %w", err)
	}
	return &anypb.Any{TypeUrl: vpcisave.TypeURL, Value: payload}, nil
}

// Import rehydrates a [Controller] from a [Controller.Save]'d envelope
// without binding any host/guest interfaces. The returned controller is
// inert until [Controller.Resume] supplies the live interfaces.
func Import(env *anypb.Any) (*Controller, error) {
	state := &vpcisave.Payload{}
	if env != nil {
		if env.GetTypeUrl() != vpcisave.TypeURL {
			return nil, fmt.Errorf("unsupported vpci saved-state type %q", env.GetTypeUrl())
		}
		if err := proto.Unmarshal(env.GetValue(), state); err != nil {
			return nil, fmt.Errorf("unmarshal vpci saved state: %w", err)
		}
		if v := state.GetSchemaVersion(); v != vpcisave.SchemaVersion {
			return nil, fmt.Errorf("unsupported vpci saved-state schema version %d (want %d)", v, vpcisave.SchemaVersion)
		}
	}

	c := &Controller{
		devices:      make(map[guid.GUID]*deviceInfo),
		deviceToGUID: make(map[Device]guid.GUID),
		isMigrating:  true,
	}

	for guidStr, d := range state.GetDevices() {
		g, err := guid.FromString(guidStr)
		if err != nil {
			continue
		}
		dev := Device{
			DeviceInstanceID:     d.GetDeviceInstanceID(),
			VirtualFunctionIndex: uint16(d.GetVirtualFunctionIndex()),
		}
		c.devices[g] = &deviceInfo{
			device:    dev,
			vmBusGUID: g,
			state:     State(d.GetState()),
			refCount:  d.GetRefCount(),
		}
		c.deviceToGUID[dev] = g
	}
	return c, nil
}

// Resume binds the live host/guest interfaces to a controller previously
// produced by [Import]. Must be called once the destination VM is running
// before any reservation or assignment APIs are invoked.
func (c *Controller) Resume(vmVPCI vmVPCI, guestVPCI guestVPCI) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.vmVPCI = vmVPCI
	c.guestVPCI = guestVPCI
	c.isMigrating = false
}
