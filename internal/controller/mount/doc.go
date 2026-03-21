//go:build windows

// Package mount manages the lifecycle of guest-level mounts for Hyper-V
// utility VMs.
//
// The [Manager] type is the primary entry point.  It exposes methods to mount
// SCSI disks inside the guest OS and release them when no longer needed.
//
// The Manager is device-agnostic at the caller level: callers supply the SCSI
// controller and LUN that identify an already-attached disk, and the Manager
// handles all guest-side mount/unmount operations.  The caller is responsible
// for ensuring the underlying SCSI attachment is present before mounting and
// for detaching it only after all mounts have been released.
//
// Internally, the Manager tracks guest-level mounts ([guestMount]), each of
// which has an explicit forward-only state machine.  Mounts are
// reference-counted so that multiple callers sharing the same guest path do
// not conflict.
//
// # State Machine
//
// Every guestMount carries a [mountState].  States move forward only; on
// partial failure the state records the furthest point reached so that a
// retry never repeats work that already succeeded.
//
// Mount lifecycle:
//
//	(none) ─ mountInGuest ─────────────► Mounted
//	Mounted ─ unmountFromGuest ────────► Unmounted
//
// # Error Handling
//
// During the mount phase, if the GCS call fails, the mount is not recorded —
// control returns to the caller with an error.
//
// During unmount, errors move the state forward and reference counts are not
// restored on failure so that a retry never repeats already-succeeded work.
package mount
