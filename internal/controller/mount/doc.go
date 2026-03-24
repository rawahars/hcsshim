//go:build windows

// Package mount manages the lifecycle of guest-level mounts for Hyper-V
// utility VMs.
//
// # Architecture
//
// The [Manager] type is the primary entry point.  It exposes a set of APIs
// that handles guest mounts for both SCSI disks and Plan9 shares,
// with a dedicated Resolve/Mount/Unmount API for each device type:
//
//   - [Manager.ResolveSCSIGuestPath] / [Manager.MountSCSI] / [Manager.UnmountSCSI]
//   - [Manager.ResolvePlan9GuestPath] / [Manager.MountPlan9] / [Manager.UnmountPlan9]
//
// Internally, Manager tracks guest-level mounts for each device type,
// each of which has its own explicit state machine.  Mounts are reference-counted
// so that multiple callers sharing the same guest path do not conflict.
// Callers should resolve the guest path prior to invoking the Mount API.
//
// # Device manager integration
//
// This package is designed to work downstream of the device managers:
//
//   - After [device.scsi.AttachDiskToVM] returns a [VMSlot], pass its
//     Controller and LUN fields to [Manager.MountSCSI].
//   - After [device.plan9.AddToVM] returns a shareName, pass it to
//     [Manager.MountPlan9].
//
// The device manager owns the host-side lifetime of the device.  The mount
// manager owns only the guest-side mount.  Callers must ensure the device
// is attached before mounting, and must unmount before detaching.
//
// # Usage
//
// Resolve the guest path before the actual mount so that downstream resources
// (e.g., OCI spec paths) can be computed without waiting for the guest call:
//
//	// SCSI
//	guestPath := mgr.ResolveSCSIGuestPath(controller, lun, mount.SCSIMountConfig{})
//	cfg := mount.SCSIMountConfig{GuestPath: guestPath}
//	guestPath, err = mgr.MountSCSI(ctx, controller, lun, cfg)
//
//	// Plan9 (LCOW only)
//	guestPath = mgr.ResolvePlan9GuestPath(shareName, mount.Plan9MountConfig{})
//	p9cfg := mount.Plan9MountConfig{GuestPath: guestPath}
//	guestPath, err = mgr.MountPlan9(ctx, shareName, p9cfg)
//
// # SCSI mounts
//
// SCSI mounts are supported on both LCOW and WCOW guests.  The Manager
// delegates to platform specific guest operator based on the build
// tag (linux shim vs. windows shim).
//
// # Plan9 mounts
//
// Plan9 mounts are LCOW-only (Plan9 is a Linux guest protocol).
// The Manager delegates to Linux guest operator for
// the actual GCS add/remove-mapped-directory requests.
//
// # Reference counting
//
// Both SCSI and Plan9 mounts are ref-counted.  When two callers mount the
// same resource at the same guest path with the same config, they share a
// single mount entry.  The guest-side unmount only happens when the last
// reference is released.
//
// # State Machine
//
// Every mount (SCSI or Plan9) carries a [mountState].  States move forward
// only.
//
// Each mount entry progresses through the states below.
// The happy path runs down the left column; the error path is on the right.
//
//	Mount operation requested
//	           │
//	           ▼
//	┌─────────────────────┐
//	│    mountPending     │
//	└──────────┬──────────┘
//	           │
//	   ┌───────┴────────────────────────────────┐
//	   │ mountInGuest succeeds                  │ mountInGuest fails
//	   ▼                                        ▼
//	┌─────────────────────┐         ┌──────────────────────┐
//	│    mountMounted     │         │     mountInvalid     │
//	└──────────┬──────────┘         └──────────┬───────────┘
//	           │ unmountFromGuest              │
//	           │   succeeds                    │
//	           ▼                               ▼
//	┌─────────────────────┐          (auto-removed from map)
//	│   mountUnmounted    │  ← terminal; entry removed from map
//	└─────────────────────┘
//
// State descriptions:
//
//   - [mountPending]: entered when a mount operation begins.
//     The guest mount call has not yet completed.
//   - [mountMounted]: entered once mountInGuest succeeds; the guest path
//     is accessible inside the VM.
//   - [mountUnmounted]: entered once unmountFromGuest succeeds;
//     the guest path is no longer accessible.  Terminal state.
//   - [mountInvalid]: entered when mountInGuest fails; concurrent waiters
//     receive the original error and the entry is removed from the map.
package mount
