//go:build windows

// Package scsi manages the lifecycle of SCSI disk attachments on a Hyper-V VM.
//
// It abstracts host-side slot allocation, reference counting, and two-phase
// teardown (guest unplug followed by host removal) behind the [Controller]
// interface, with [Manager] as the primary implementation.
//
// # Lifecycle
//
// Each disk attachment progresses through the states below:
//
//	┌──────────────────────┐
//	│  attachmentAttached  │◄── [Manager.AttachDiskToVM] succeeds
//	└──────────┬───────────┘
//	           │ unplugFromGuest succeeds
//	           ▼
//	┌──────────────────────┐
//	│ attachmentUnplugged  │
//	└──────────┬───────────┘
//	           │ RemoveSCSIDisk succeeds
//	           ▼
//	┌──────────────────────┐
//	│  attachmentDetached  │  (terminal — slot freed)
//	└──────────────────────┘
//
//	┌──────────────────────┐
//	│  attachmentReserved  │  (no transitions — pre-reserved at construction)
//	└──────────────────────┘
//
// State descriptions:
//
//   - [attachmentAttached]: entered once [AddSCSIDisk] succeeds;
//     the disk is on the SCSI bus and available for guest mounts.
//   - [attachmentUnplugged]: entered once the guest-side unplug completes;
//     the guest has released the device but the host has not yet removed it.
//   - [attachmentDetached]: terminal state entered once [RemoveSCSIDisk] succeeds.
//   - [attachmentReserved]: special state for slots pre-reserved via [New];
//     these are never allocated to new disks and never torn down.
//
// # Reference Counting
//
// Multiple callers may request the same disk (identical host path, type, and
// read-only flag). [Manager.AttachDiskToVM] detects duplicates and increments a
// reference count instead of issuing a second HCS call; the slot is shared.
// [Manager.DetachFromVM] decrements the count and only tears down the attachment
// when it reaches zero.
//
// # Platform Variants
//
// The guest-side unplug step differs between LCOW and WCOW guests and is
// selected via build tags (default for the LCOW shim; "wcow" tag for the WCOW shim):
//
//   - LCOW: sends a SCSIDevice removal request to the Guest Compute Service (GCS),
//     which hot-unplugs the device from the Linux kernel before the host removes the disk.
//   - WCOW: unplugFromGuest is a no-op; Windows handles SCSI hot-unplug
//     automatically when the host removes the disk from the VM.
//
// # Usage
//
//	mgr := scsi.New(vmScsiManager, linuxGuestMgr, numControllers, reservedSlots)
//
//	slot, err := mgr.AttachDiskToVM(ctx, "/path/to/disk.vhdx", scsi.DiskTypeVirtualDisk, false)
//	if err != nil {
//	    // handle error
//	}
//
//	// ... use slot for guest mounts ...
//
//	if err := mgr.DetachFromVM(ctx, slot); err != nil {
//	    // handle error
//	}
package scsi
