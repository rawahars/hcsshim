//go:build windows

// Package scsi manages the full lifecycle of SCSI disk mappings on a
// Hyper-V VM, from host-side slot allocation through guest-side mounting.
//
// # Architecture
//
// [Manager] is the primary entry point, exposing two methods:
//
//   - [Manager.MapToGuest]: allocates a SCSI slot (if needed), attaches the
//     disk to the VM's SCSI bus, and mounts the specified partition inside the
//     guest. The caller supplies a stable mappingID that identifies the mapping
//     across retries.
//   - [Manager.UnmapFromGuest]: unmounts the partition from the guest, and
//     when all mappings for an attachment are released, unplugs the SCSI
//     device and detaches the disk from the VM.
//
// All operations are serialized by a single mutex on the [Manager]. Guest
// paths are always auto-generated; callers cannot supply their own.
//
// # Layered State Model
//
// The state is tracked at two layers:
//
//   - [attachment]: represents a disk on the VM's SCSI bus (one per [VMSlot]).
//     States: attachPending → attachAttached → attachDetaching → attachUnplugged → attachDetached.
//   - [mount]: represents a partition mounted inside the guest (keyed by
//     partition index within an attachment).
//     States: mountPending → mountMounted → mountUnmounted.
//
// A third structure, [mapping], links a caller-supplied mappingID to an
// [attachment] and partition index. It carries no lifecycle state of its own;
// the [attachment] and [mount] state machines drive all transitions.
//
// # Retry / Idempotency
//
// Both [Manager.MapToGuest] and [Manager.UnmapFromGuest] are designed to be
// retriable. On failure, the [attachment] and [mount] states remain at their
// pre-operation position (no poisoning). A subsequent call with the same
// mappingID resumes from where the previous attempt stopped.
//
// Calling [Manager.MapToGuest] with the same mappingID after a successful call
// is a no-op that returns the existing guest path.
//
// # Attachment Lifecycle
//
//	┌──────────────────┐
//	│  attachPending   │ ← stays here on attach failure (retriable)
//	└────────┬─────────┘
//	         │ disk added to VM SCSI bus
//	         ▼
//	┌──────────────────┐
//	│ attachAttached   │
//	└────────┬─────────┘
//	  (mounts driven here)
//	         │ all partitions released;
//	         │ detach initiated
//	         ▼
//	┌──────────────────┐
//	│ attachDetaching  │ ← stays here on unplug failure (retriable)
//	└────────┬─────────┘
//	         │ SCSI device unplugged from guest
//	         ▼
//	┌──────────────────┐
//	│ attachUnplugged  │
//	└────────┬─────────┘
//	         │ disk removed from VM SCSI bus
//	         ▼
//	┌──────────────────┐
//	│ attachDetached   │
//	└──────────────────┘
//	  (entry removed from map)
//
//	┌──────────────────┐
//	│ attachReserved   │  ← no transitions; pre-reserved at construction
//	└──────────────────┘
//
// # Mount Lifecycle
//
//	┌──────────────────┐
//	│  mountPending    │ ← stays here on mount failure (retriable)
//	└────────┬─────────┘
//	         │ guest mount succeeds
//	         ▼
//	┌──────────────────┐
//	│  mountMounted    │
//	└────────┬─────────┘
//	         │ refCount → 0;
//	         │ guest unmount
//	         ▼
//	┌──────────────────┐
//	│ mountUnmounted   │
//	└──────────────────┘
//	  (partition entry removed from attachment)
//
// # Reference Counting
//
// Multiple mappingIDs may target the same disk and partition. [Manager.MapToGuest]
// detects duplicates and increments a reference count on the [mount] instead of
// issuing duplicate guest operations; the guest path is shared.
//
// [Manager.UnmapFromGuest] decrements the count and only unmounts when it reaches
// zero.
//
// # Platform Variants
//
// Guest-side mount, unmount, and unplug steps differ between LCOW and WCOW
// guests and are selected via build tags (default for the LCOW shim;
// "wcow" tag for the WCOW shim):
//
//   - LCOW: mounts via AddLCOWMappedVirtualDisk, unmounts via
//     RemoveLCOWMappedVirtualDisk, and unplugs via RemoveSCSIDevice.
//   - WCOW: mounts via AddWCOWMappedVirtualDisk (or
//     AddWCOWMappedVirtualDiskForContainerScratch for scratch disks),
//     unmounts via RemoveWCOWMappedVirtualDisk; unplug is a no-op because
//     Windows handles SCSI hot-unplug automatically when the host removes
//     the disk from the VM.
//
// # Usage
//
//	mgr := scsi.New(vmID, vmScsi, linuxGuestScsi, windowsGuestScsi, numControllers, reservedSlots)
//
//	diskConfig := scsi.DiskConfig{HostPath: "/path/to/disk.vhdx", Type: scsi.DiskTypeVirtualDisk}
//	mountConfig := scsi.MountConfig{ReadOnly: true}
//
//	// Map the disk to the guest (allocate slot + attach + mount):
//	guestPath, err := mgr.MapToGuest(ctx, "container-abc/layer-0", diskConfig, mountConfig)
//	if err != nil {
//	    // Retry with the same mappingID to resume:
//	    guestPath, err = mgr.MapToGuest(ctx, "container-abc/layer-0", diskConfig, mountConfig)
//	}
//
//	// Unmap (unmount + unplug + detach when last mapping):
//	if err := mgr.UnmapFromGuest(ctx, "container-abc/layer-0"); err != nil {
//	    // Retry:
//	    _ = mgr.UnmapFromGuest(ctx, "container-abc/layer-0")
//	}
package scsi
