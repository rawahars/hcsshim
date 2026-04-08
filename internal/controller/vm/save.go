//go:build windows

package vm

import (
	migration "github.com/Microsoft/hcsshim/sandbox-spec/migration/v2"
)

// Save returns a proto snapshot of the VM controller's current state.
func (c *Controller) Save() *migration.VMControllerState {
	c.mu.RLock()
	defer c.mu.RUnlock()

	protoState := &migration.VMControllerState{
		VmID:                 c.vmID,
		State:                vmStateToProto(c.vmState),
		IsPhysicallyBacked:   c.isPhysicallyBacked,
		NoWritableFileShares: c.noWritableFileShares,
	}

	// Delegate to each device controller's Save.
	if c.scsiController != nil {
		protoState.Scsi = c.scsiController.Save()
	}
	if c.plan9Controller != nil {
		protoState.Plan9 = c.plan9Controller.Save()
	}
	if c.vpciController != nil {
		protoState.Vpci = c.vpciController.Save()
	}

	return protoState
}

func vmStateToProto(s State) migration.VMLifecycleState {
	switch s {
	case StateNotCreated:
		return migration.VMLifecycleState_VM_STATE_NOT_CREATED
	case StateCreated:
		return migration.VMLifecycleState_VM_STATE_CREATED
	case StateRunning:
		return migration.VMLifecycleState_VM_STATE_RUNNING
	case StateTerminated:
		return migration.VMLifecycleState_VM_STATE_TERMINATED
	case StateInvalid:
		return migration.VMLifecycleState_VM_STATE_INVALID
	default:
		return migration.VMLifecycleState_VM_STATE_NOT_CREATED
	}
}
