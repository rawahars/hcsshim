//go:build windows && lcow

package vm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Microsoft/hcsshim/internal/builder/vm/lcow"
	"github.com/Microsoft/hcsshim/internal/controller/device/plan9"
	"github.com/Microsoft/hcsshim/internal/controller/device/scsi"
	"github.com/Microsoft/hcsshim/internal/controller/device/vpci"
	vmsave "github.com/Microsoft/hcsshim/internal/controller/vm/save"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// Save returns the VM controller's migration payload as an [anypb.Any]
// tagged with [vmsave.TypeURL]. The returned envelope includes the
// host-emitted compatibility blob and the opaque [anypb.Any] envelopes
// produced by every attached sub-controller (SCSI, VPCI, Plan9), which
// the VM controller treats as opaque.
func (c *Controller) Save(ctx context.Context) (*anypb.Any, error) {
	// CompatibilityInfo takes its own read lock; fetch it before acquiring
	// ours to avoid recursive RLock acquisition.
	compatInfo, err := c.CompatibilityInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("get compatibility info: %w", err)
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	state := &vmsave.Payload{
		VmID:           c.vmID,
		State:          vmsave.Stage(c.vmState),
		SandboxOptions: sandboxOptionsToProto(c.sandboxOptions),
		CompatInfo:     compatInfo,
	}

	// Ship the final HCS ComputeSystem document so the destination can
	// recreate an identical VM. We encode it as JSON because the schema is
	// owned by hcsschema (not protobuf) and JSON is the canonical wire
	// format HCS itself consumes.
	if c.hcsDocument != nil {
		docBytes, err := json.Marshal(c.hcsDocument)
		if err != nil {
			return nil, fmt.Errorf("marshal hcs document: %w", err)
		}
		state.HcsDocument = docBytes
	}

	if c.scsiController != nil {
		s, err := c.scsiController.Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("save scsi controller: %w", err)
		}
		state.Scsi = s
	}
	if c.vpciController != nil {
		v, err := c.vpciController.Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("save vpci controller: %w", err)
		}
		state.Vpci = v
	}
	if c.plan9Controller != nil {
		p, err := c.plan9Controller.Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("save plan9 controller: %w", err)
		}
		state.Plan9 = p
	}
	if p := c.guest.NextPort(); p != 0 {
		state.GcsNextPort = p
	}

	payload, err := proto.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("marshal vm saved state: %w", err)
	}
	return &anypb.Any{TypeUrl: vmsave.TypeURL, Value: payload}, nil
}

// Import rehydrates the controller's static state from a [Save]'d envelope.
// The controller is placed in [StateMigrating] and stays inert — along with
// its sub-controllers — until [Controller.Resume] supplies the live VM and
// the next state.
func (c *Controller) Import(env *anypb.Any) error {
	if env == nil {
		return fmt.Errorf("vm saved-state envelope is nil")
	}
	if env.GetTypeUrl() != vmsave.TypeURL {
		return fmt.Errorf("unsupported vm saved-state type %q", env.GetTypeUrl())
	}

	state := &vmsave.Payload{}
	if err := proto.Unmarshal(env.GetValue(), state); err != nil {
		return fmt.Errorf("unmarshal vm saved state: %w", err)
	}
	if v := state.GetSchemaVersion(); v != vmsave.SchemaVersion {
		return fmt.Errorf("unsupported vm saved-state schema version %d (want %d)", v, vmsave.SchemaVersion)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.vmID = state.GetVmID()
	c.sandboxOptions = sandboxOptionsFromProto(state.GetSandboxOptions())
	if c.sandboxOptions != nil {
		c.isPhysicallyBacked = c.sandboxOptions.FullyPhysicallyBacked
	}
	c.vmState = StateMigrating

	// Decode the HCS document so [Controller.CreateVM] (called next on the
	// destination with MigrationOptions populated) can reuse it verbatim.
	if raw := state.GetHcsDocument(); len(raw) > 0 {
		doc := &hcsschema.ComputeSystem{}
		if err := json.Unmarshal(raw, doc); err != nil {
			return fmt.Errorf("unmarshal hcs document: %w", err)
		}
		c.hcsDocument = doc
	}

	if env := state.GetScsi(); env != nil {
		s, err := scsi.Import(env)
		if err != nil {
			return fmt.Errorf("import scsi controller: %w", err)
		}
		c.scsiController = s
	}
	if env := state.GetVpci(); env != nil {
		v, err := vpci.Import(env)
		if err != nil {
			return fmt.Errorf("import vpci controller: %w", err)
		}
		c.vpciController = v
	}
	if env := state.GetPlan9(); env != nil {
		p, err := plan9.Import(env)
		if err != nil {
			return fmt.Errorf("import plan9 controller: %w", err)
		}
		c.plan9Controller = p
	}

	return nil
}

// Resume binds the live HCS utility VM and guest manager to a controller
// previously produced by [Import] and transitions it from [StateMigrating]
// into next. After it returns the controller and its sub-controllers are
// ready for host/guest-driven operations.
func (c *Controller) Resume(_ context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.scsiController != nil {
		c.scsiController.Resume(c.uvm, c.guest)
	}
	if c.vpciController != nil {
		c.vpciController.Resume(c.uvm, c.guest)
	}
	if c.plan9Controller != nil {
		c.plan9Controller.Resume(c.uvm, c.guest)
	}
}

func sandboxOptionsToProto(o *lcow.SandboxOptions) *vmsave.SandboxOptions {
	if o == nil {
		return nil
	}
	out := &vmsave.SandboxOptions{
		NoWritableFileShares:    o.NoWritableFileShares,
		EnableScratchEncryption: o.EnableScratchEncryption,
		PolicyBasedRouting:      o.PolicyBasedRouting,
		Architecture:            o.Architecture,
		FullyPhysicallyBacked:   o.FullyPhysicallyBacked,
	}
	if o.ConfidentialConfig != nil {
		out.Confidential = &vmsave.ConfidentialConfig{
			SecurityPolicy:         o.ConfidentialConfig.SecurityPolicy,
			SecurityPolicyEnforcer: o.ConfidentialConfig.SecurityPolicyEnforcer,
			UvmReferenceInfoFile:   o.ConfidentialConfig.UvmReferenceInfoFile,
		}
	}
	return out
}

func sandboxOptionsFromProto(p *vmsave.SandboxOptions) *lcow.SandboxOptions {
	if p == nil {
		return nil
	}
	out := &lcow.SandboxOptions{
		NoWritableFileShares:    p.GetNoWritableFileShares(),
		EnableScratchEncryption: p.GetEnableScratchEncryption(),
		PolicyBasedRouting:      p.GetPolicyBasedRouting(),
		Architecture:            p.GetArchitecture(),
		FullyPhysicallyBacked:   p.GetFullyPhysicallyBacked(),
	}
	if c := p.GetConfidential(); c != nil {
		out.ConfidentialConfig = &lcow.ConfidentialConfig{
			SecurityPolicy:         c.GetSecurityPolicy(),
			SecurityPolicyEnforcer: c.GetSecurityPolicyEnforcer(),
			UvmReferenceInfoFile:   c.GetUvmReferenceInfoFile(),
		}
	}
	return out
}
