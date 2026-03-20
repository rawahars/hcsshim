//go:build windows

package scsi

import "context"

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

// Controller is the primary interface for attaching and detaching SCSI disks on a VM.
type Controller interface {
	// AttachDiskToVM attaches the disk at hostPath to the VM and returns the allocated [VMSlot].
	// If the same disk is already attached, the existing slot is reused.
	AttachDiskToVM(ctx context.Context, hostPath string, diskType DiskType, readOnly bool) (VMSlot, error)

	// DetachFromVM unplugs and detaches the disk from the VM.
	DetachFromVM(ctx context.Context, slot VMSlot) error
}

// VMSlot identifies a disk's hardware address on the VM's SCSI bus.
type VMSlot struct {
	// Controller is the zero-based SCSI controller index.
	Controller uint
	// LUN is the logical unit number within the controller.
	LUN uint
}

// ==============================================================================
// INTERNAL DATA STRUCTURES
// Types and constants below this line are unexported and used for state tracking.
// ==============================================================================

// numLUNsPerController is the maximum number of LUNs per controller, fixed by Hyper-V.
const numLUNsPerController = 64

// diskConfig holds the immutable parameters that uniquely identify a disk attachment request.
type diskConfig struct {
	hostPath string
	readOnly bool
	typ      DiskType
	// evdType is the EVD provider name; only populated when typ is [DiskTypeExtensibleVirtualDisk].
	evdType string
}

// vmAttachment records one disk's full attachment state and reference count.
type vmAttachment struct {
	// config is the immutable disk parameters used to match duplicate attach requests.
	config *diskConfig

	// controller and lun are the allocated hardware address on the SCSI bus.
	controller uint
	lun        uint

	// refCount is the number of active callers sharing this attachment.
	// Access must be guarded by [Manager.mu].
	refCount uint

	// state tracks the forward-only lifecycle position of this attachment.
	// Access must be guarded by [Manager.mu].
	state attachmentState

	// waitCh is closed (with waitErr set) once the HCS attach call for this
	// attachment has finished.
	waitCh  chan struct{}
	waitErr error
}
