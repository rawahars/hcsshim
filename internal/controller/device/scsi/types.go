//go:build windows

package scsi

import (
	"context"
	"sync"

	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
)

// DiskType identifies the attachment protocol used when adding a disk to the VM's SCSI bus.
type DiskType string

const (
	// DiskTypeVirtualDisk attaches the disk as a virtual hard disk (VHD/VHDX).
	DiskTypeVirtualDisk DiskType = "VirtualDisk"

	// DiskTypePassThru attaches a physical disk directly to the VM with pass-through access.
	DiskTypePassThru DiskType = "PassThru"

	// DiskTypeExtensibleVirtualDisk attaches a disk via an extensible virtual disk (EVD) provider.
	// The hostPath must be in the form evd://<type>/<mountPath>.
	DiskTypeExtensibleVirtualDisk DiskType = "ExtensibleVirtualDisk"
)

type DiskConfig struct {
	// HostPath is the path on the host to the disk to be attached.
	HostPath string
	// ReadOnly specifies whether the disk should be attached with read-only access.
	ReadOnly bool
	// Type specifies the attachment protocol to use when attaching the disk.
	Type DiskType
	// EVDType is the EVD provider name.
	// Only populated when Type is [DiskTypeExtensibleVirtualDisk].
	EVDType string
}

// VMSlot identifies a disk's hardware address on the VM's SCSI bus.
type VMSlot struct {
	// Controller is the zero-based SCSI controller index.
	Controller uint
	// LUN is the logical unit number within the controller.
	LUN uint
}

// ==============================================================================
// Interfaces used by Manager to perform actions on VM and Guest.
// ==============================================================================

// vmSCSI manages adding and removing SCSI devices for a Utility VM.
type vmSCSI interface {
	// AddSCSIDisk hot adds a SCSI disk to the Utility VM.
	AddSCSIDisk(ctx context.Context, disk hcsschema.Attachment, controller uint, lun uint) error

	// RemoveSCSIDisk removes a SCSI disk from a Utility VM.
	RemoveSCSIDisk(ctx context.Context, controller uint, lun uint) error
}

// linuxGuestSCSI exposes mapped virtual disk and SCSI device operations in the LCOW guest.
type linuxGuestSCSI interface {
	// AddLCOWMappedVirtualDisk maps a virtual disk into the LCOW guest.
	AddLCOWMappedVirtualDisk(ctx context.Context, settings guestresource.LCOWMappedVirtualDisk) error
	// RemoveLCOWMappedVirtualDisk unmaps a virtual disk from the LCOW guest.
	RemoveLCOWMappedVirtualDisk(ctx context.Context, settings guestresource.LCOWMappedVirtualDisk) error
	// RemoveSCSIDevice removes a SCSI device from the guest.
	RemoveSCSIDevice(ctx context.Context, settings guestresource.SCSIDevice) error
}

// ==============================================================================
// INTERNAL DATA STRUCTURES
// Types and constants below this line are unexported and used for state tracking.
// ==============================================================================

// numLUNsPerController is the maximum number of LUNs per controller, fixed by Hyper-V.
const numLUNsPerController = 64

// vmAttachment records one disk's full attachment state and reference count.
type vmAttachment struct {
	// mu serializes state transitions and broadcasts completion to concurrent waiters.
	mu sync.Mutex

	// config is the immutable disk parameters used to match duplicate attach requests.
	config *DiskConfig

	// controller and lun are the allocated hardware address on the SCSI bus.
	controller uint
	lun        uint

	// refCount is the number of active callers sharing this attachment.
	// Access must be guarded by [Manager.mu].
	refCount uint

	// state tracks the forward-only lifecycle position of this attachment.
	// Access must be guarded by [Manager.mu].
	state attachmentState

	// stateErr records the error that caused a transition to [attachmentInvalid].
	// Waiters that find the attachment in the invalid state return this error so
	// that every caller sees the original failure reason.
	stateErr error
}
