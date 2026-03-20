//go:build windows

package scsi

// attachmentState represents the current state of a SCSI disk attachment lifecycle.
//
// The normal progression is:
//
//	attachmentAttached → attachmentUnplugged → attachmentDetached
//
// attachmentReserved is a special state for pre-reserved slots that never
// transition to any other state.
//
// Full state-transition table:
//
//	Current State           │ Trigger                            │ Next State
//	────────────────────────┼────────────────────────────────────┼────────────────────
//	attachmentAttached      │ unplugFromGuest succeeds           │ attachmentUnplugged
//	attachmentUnplugged     │ RemoveSCSIDisk succeeds            │ attachmentDetached
//	attachmentDetached      │ (terminal — no further transitions)│ —
//	attachmentReserved      │ (never transitions)                │ —
type attachmentState int

const (
	// attachmentAttached means AddSCSIDisk succeeded; the disk is on the SCSI
	// bus and available for guest mounts.
	// Valid transitions:
	//   - attachmentAttached → attachmentUnplugged (via unplugFromGuest, on success)
	attachmentAttached attachmentState = iota

	// attachmentUnplugged means unplugFromGuest succeeded; the guest has
	// released the device but RemoveSCSIDisk has not yet been called.
	// Valid transitions:
	//   - attachmentUnplugged → attachmentDetached (via RemoveSCSIDisk, on success)
	attachmentUnplugged

	// attachmentDetached means RemoveSCSIDisk succeeded; the disk has been
	// fully removed from the VM. This is a terminal state.
	attachmentDetached

	// attachmentReserved is used for slots pre-reserved at Manager construction
	// time. These must never be handed out or torn down — no transitions are valid.
	attachmentReserved
)

// String returns a human-readable name for the [attachmentState].
func (s attachmentState) String() string {
	switch s {
	case attachmentAttached:
		return "Attached"
	case attachmentUnplugged:
		return "Unplugged"
	case attachmentDetached:
		return "Detached"
	case attachmentReserved:
		return "Reserved"
	default:
		return "Unknown"
	}
}
