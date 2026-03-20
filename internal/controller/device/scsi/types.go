//go:build windows

package scsi

import (
	"context"
	"slices"

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

// DiskConfig describes the host-side disk to attach to the VM's SCSI bus.
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

// MountConfig describes how a partition of a SCSI disk should be mounted inside the guest.
type MountConfig struct {
	// Partition is the target partition index (1-based) on a partitioned device.
	// Zero means the whole disk.
	Partition uint64
	// ReadOnly mounts the disk read-only.
	ReadOnly bool
	// Encrypted encrypts the device with dm-crypt.
	// Only supported for LCOW.
	Encrypted bool
	// Options are mount flags or data passed to the guest mount call.
	// Only supported for LCOW.
	Options []string
	// EnsureFilesystem formats the mount as Filesystem if not already formatted.
	// Only supported for LCOW.
	EnsureFilesystem bool
	// Filesystem is the target filesystem type.
	// Only supported for LCOW.
	Filesystem string
	// BlockDev mounts the device as a block device.
	// Only supported for LCOW.
	BlockDev bool
	// FormatWithRefs formats the disk using refs.
	// Only supported for WCOW scratch disks.
	FormatWithRefs bool
}

// VMSlot identifies a disk's hardware address on the VM's SCSI bus.
type VMSlot struct {
	// Controller is the zero-based SCSI controller index.
	Controller uint
	// LUN is the logical unit number within the controller.
	LUN uint
}

// equals reports whether two DiskConfig values describe the same attachment parameters.
func (d DiskConfig) equals(other DiskConfig) bool {
	return d.HostPath == other.HostPath &&
		d.ReadOnly == other.ReadOnly &&
		d.Type == other.Type &&
		d.EVDType == other.EVDType
}

// equals reports whether two MountConfig values describe the same mount parameters.
func (mc MountConfig) equals(other MountConfig) bool {
	return mc.ReadOnly == other.ReadOnly &&
		mc.Encrypted == other.Encrypted &&
		mc.EnsureFilesystem == other.EnsureFilesystem &&
		mc.Filesystem == other.Filesystem &&
		mc.BlockDev == other.BlockDev &&
		mc.FormatWithRefs == other.FormatWithRefs &&
		slices.Equal(mc.Options, other.Options)
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

// linuxGuestSCSI exposes guest-side SCSI operations for LCOW guests,
// including mount, unmount, and device-level unplug.
type linuxGuestSCSI interface {
	// AddLCOWMappedVirtualDisk maps a virtual disk into the LCOW guest.
	AddLCOWMappedVirtualDisk(ctx context.Context, settings guestresource.LCOWMappedVirtualDisk) error
	// RemoveLCOWMappedVirtualDisk unmaps a virtual disk from the LCOW guest.
	RemoveLCOWMappedVirtualDisk(ctx context.Context, settings guestresource.LCOWMappedVirtualDisk) error
	// RemoveSCSIDevice removes a SCSI device from the guest.
	RemoveSCSIDevice(ctx context.Context, settings guestresource.SCSIDevice) error
}

// windowsGuestSCSI performs WCOW SCSI guest mount/unmount operations.
type windowsGuestSCSI interface {
	// AddWCOWMappedVirtualDisk maps a virtual disk into the WCOW guest.
	AddWCOWMappedVirtualDisk(ctx context.Context, settings guestresource.WCOWMappedVirtualDisk) error
	// AddWCOWMappedVirtualDiskForContainerScratch maps a virtual disk as a container scratch in the WCOW guest.
	AddWCOWMappedVirtualDiskForContainerScratch(ctx context.Context, settings guestresource.WCOWMappedVirtualDisk) error
	// RemoveWCOWMappedVirtualDisk unmaps a virtual disk from the WCOW guest.
	RemoveWCOWMappedVirtualDisk(ctx context.Context, settings guestresource.WCOWMappedVirtualDisk) error
}

// ==============================================================================
// INTERNAL DATA STRUCTURES
// Types and constants below this line are unexported and used for state tracking.
// ==============================================================================

// numLUNsPerController is the maximum number of LUNs per controller, fixed by Hyper-V.
const numLUNsPerController = 64

// attachment records the lifecycle state of a SCSI disk on the VM's SCSI bus.
// Access must be guarded by Manager.mu.
type attachment struct {
	// controller and lun are the allocated hardware address on the SCSI bus.
	controller uint
	lun        uint

	// diskConfig is the immutable host-side disk parameters.
	diskConfig *DiskConfig

	// state tracks the lifecycle position of this attachment.
	state attachState

	// partitions maps a partition index to its guest mount state.
	// Partition 0 represents the whole disk.
	partitions map[uint64]*mount
}

// mount records the lifecycle state of a single partition mount inside the guest.
// Access must be guarded by Manager.mu.
type mount struct {
	// config is the immutable guest-side mount parameters.
	config *MountConfig

	// guestPath is the auto-generated path inside the guest where the partition
	// is mounted.
	guestPath string

	// refCount is the number of active callers sharing this mount.
	refCount uint

	// state tracks the lifecycle position of this mount.
	state mountState
}

// mapping links a caller-supplied mappingID to an attachment and partition
// index. Access must be guarded by Manager.mu.
type mapping struct {
	// att is the SCSI attachment this mapping references.
	att *attachment

	// partition is the partition index on the device (0 = whole disk).
	partition uint64
}
