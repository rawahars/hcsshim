//go:build windows

package scsi

// attachState represents the current state of a SCSI disk attachment lifecycle.
//
// The normal progression is:
//
//	attachPending → attachAttached → attachDetaching → attachUnplugged → attachDetached
//
// If the attach operation fails, the state remains at attachPending so
// the caller can retry. attachReserved is a terminal state for
// pre-reserved slots.
//
// Full state-transition table:
//
//	Current State        │ Trigger                            │ Next State
//	─────────────────────┼────────────────────────────────────┼────────────────────
//	attachPending        │ attach succeeds                    │ attachAttached
//	attachPending        │ attach fails                       │ attachPending
//	attachAttached       │ detach begins                      │ attachDetaching
//	attachDetaching      │ guest unplug succeeds              │ attachUnplugged
//	attachUnplugged      │ bus removal succeeds               │ attachDetached
//	attachDetached       │ (terminal — no further transitions)│ —
//	attachReserved       │ (terminal — no further transitions)│ —
type attachState int

const (
	// attachPending is the initial state; the slot has been allocated but
	// the disk has not yet been added to the VM's SCSI bus.
	attachPending attachState = iota

	// attachAttached means the disk has been added to the VM's SCSI bus.
	attachAttached

	// attachDetaching means a detach has been initiated but the guest has
	// not yet unplugged the device.
	attachDetaching

	// attachUnplugged means the guest has unplugged the device but it has
	// not yet been removed from the VM's SCSI bus.
	attachUnplugged

	// attachDetached means the disk has been fully removed from the VM's
	// SCSI bus. This is a terminal state.
	attachDetached

	// attachReserved marks a slot pre-reserved at manager construction
	// time. This is a terminal state.
	attachReserved
)

// String returns a human-readable name for the [attachState].
func (s attachState) String() string {
	switch s {
	case attachPending:
		return "Pending"
	case attachAttached:
		return "Attached"
	case attachDetaching:
		return "Detaching"
	case attachUnplugged:
		return "Unplugged"
	case attachDetached:
		return "Detached"
	case attachReserved:
		return "Reserved"
	default:
		return "Unknown"
	}
}

// mountState represents the current state of a partition mount inside the guest.
//
// The normal progression is:
//
//	mountPending → mountMounted → mountUnmounted
//
// If the mount operation fails, the state remains at mountPending so
// the caller can retry. Once a mount reaches mountUnmounted its entry is
// deleted from the attachment's partition map; a subsequent MapToGuest call
// creates a fresh mount struct from scratch rather than transitioning out of
// this state.
//
// Full state-transition table:
//
//	Current State        │ Trigger                            │ Next State
//	─────────────────────┼────────────────────────────────────┼────────────────────
//	mountPending         │ guest mount succeeds               │ mountMounted
//	mountPending         │ guest mount fails                  │ mountPending
//	mountMounted         │ guest unmount succeeds             │ mountUnmounted
//	mountUnmounted       │ (terminal — entry removed from map)│ —
type mountState int

const (
	// mountPending is the initial state; the mount entry has been reserved
	// but the guest mount operation has not yet succeeded.
	mountPending mountState = iota

	// mountMounted means the partition has been successfully mounted inside
	// the guest.
	mountMounted

	// mountUnmounted means the guest has unmounted the partition but the
	// SCSI device may still be attached to the VM. This is a terminal state.
	mountUnmounted
)

// String returns a human-readable name for the [mountState].
func (s mountState) String() string {
	switch s {
	case mountPending:
		return "Pending"
	case mountMounted:
		return "Mounted"
	case mountUnmounted:
		return "Unmounted"
	default:
		return "Unknown"
	}
}
