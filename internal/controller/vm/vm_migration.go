//go:build windows && lcow

package vm

import (
	"context"
	"encoding/json"
	"fmt"

	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
)

// compatibilityInfoProperty is the HCS property name used to retrieve the
// VM's opaque migration-compatibility blob via PropertiesV3.
const compatibilityInfoProperty = "CompatibilityInfo"

// todo: gate all VM ops on state migrating.

// InitializeLiveMigrationOnSource initializes a live migration on the source side
// of the running VM with the provided options.
func (c *Controller) InitializeLiveMigrationOnSource(ctx context.Context, options *hcsschema.MigrationInitializeOptions) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.vmState != StateRunning {
		return fmt.Errorf("cannot initialize live migration on source: VM is in state %s", c.vmState)
	}

	if err := c.uvm.InitializeLiveMigrationOnSource(ctx, options); err != nil {
		return fmt.Errorf("failed to initialize live migration on source: %w", err)
	}

	// Transition to Migrating: only live-migration APIs are permitted from here on.
	c.vmState = StateMigrating
	return nil
}

// CompatibilityInfo returns the opaque, host-emitted compatibility blob for
// this VM. The destination shim hands it back to HCS when starting the target
// VM so the platform can verify that source and destination hosts can
// interchange live-migration state.
func (c *Controller) CompatibilityInfo(ctx context.Context) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.vmState != StateRunning && c.vmState != StateMigrating {
		return nil, fmt.Errorf("cannot query compatibility info: VM is in state %s", c.vmState)
	}

	// Query the compatibility information.
	props, err := c.uvm.PropertiesV3(ctx, &hcsschema.PropertyQuery{
		Queries: map[string]interface{}{compatibilityInfoProperty: nil},
	})
	if err != nil {
		return nil, fmt.Errorf("query compatibility info: %w", err)
	}

	resp, ok := props.PropertyResponses[compatibilityInfoProperty]
	if !ok || len(resp.Response) == 0 {
		return nil, fmt.Errorf("compatibility info not present in property response")
	}

	var info hcsschema.CompatibilityInfo
	if err := json.Unmarshal(resp.Response, &info); err != nil {
		return nil, fmt.Errorf("decode compatibility info: %w", err)
	}
	return info.Data, nil
}
