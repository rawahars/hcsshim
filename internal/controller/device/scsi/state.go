//go:build windows

package scsi

// attachmentState represents the current state of a SCSI disk attachment lifecycle.
//
// The normal progression is:
//
//	attachmentPending → attachmentAttached → attachmentUnplugged → attachmentDetached
//
// If AddSCSIDisk fails, the owning goroutine moves the attachment to
// attachmentInvalid and records the error. Other goroutines waiting on
// the same attachment observe the invalid state and receive the original
// error. The caller must call DetachFromVM to remove the map entry.
//
// attachmentReserved is a special state for pre-reserved slots that never
// transition to any other state.
//
// Full state-transition table:
//
//	Current State           │ Trigger                            │ Next State
//	────────────────────────┼────────────────────────────────────┼────────────────────
//	attachmentPending       │ AddSCSIDisk succeeds               │ attachmentAttached
//	attachmentPending       │ AddSCSIDisk fails                  │ attachmentInvalid
//	attachmentAttached      │ unplugFromGuest succeeds           │ attachmentUnplugged
//	attachmentUnplugged     │ RemoveSCSIDisk succeeds            │ attachmentDetached
//	attachmentDetached      │ (terminal — no further transitions)│ —
//	attachmentInvalid       │ DetachFromVM removes entry         │ —
//	attachmentReserved      │ (never transitions)                │ —
type attachmentState int

const (
	// attachmentPending is the initial state; AddSCSIDisk has been called but
	// has not yet completed.
	attachmentPending attachmentState = iota

	// attachmentAttached means AddSCSIDisk succeeded; the disk is on the SCSI
	// bus and available for guest mounts.
	attachmentAttached

	// attachmentUnplugged means unplugFromGuest succeeded; the guest has
	// released the device but RemoveSCSIDisk has not yet been called.
	attachmentUnplugged

	// attachmentDetached means RemoveSCSIDisk succeeded; the disk has been
	// fully removed from the VM. This is a terminal state.
	attachmentDetached

	// attachmentInvalid means AddSCSIDisk failed. The caller must call
	// [Manager.DetachFromVM] to remove the map entry and free the slot.
	attachmentInvalid

	// attachmentReserved is used for slots pre-reserved at Manager construction
	// time. These must never be handed out or torn down — no transitions are valid.
	attachmentReserved
)

// String returns a human-readable name for the [attachmentState].
func (s attachmentState) String() string {
	switch s {
	case attachmentPending:
		return "Pending"
	case attachmentAttached:
		return "Attached"
	case attachmentUnplugged:
		return "Unplugged"
	case attachmentDetached:
		return "Detached"
	case attachmentInvalid:
		return "Invalid"
	case attachmentReserved:
		return "Reserved"
	default:
		return "Unknown"
	}
}
