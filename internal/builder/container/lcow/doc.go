//go:build windows && lcow

// Package lcow prepares everything needed to create a Linux container inside a
// utility VM. The container [controller] drives it in two phases:
//
//  1. Resource reservation — [ReserveAll] orchestrates [parseAndReserveLayers],
//     [reserveAndUpdateMounts], and [reserveAndUpdateDevices] to claim host-side
//     SCSI, Plan9, and vPCI resources. It rewrites the OCI spec in place so that
//     mount sources and device IDs reference their guest-visible paths.
//     Each sub-function returns partial results on error so that a single
//     deferred [container.ResourcePlan.Release] in ReserveAll cleans up every
//     reservation that was successfully made — no per-function rollback needed.
//
//  2. Spec generation — [GenerateSpecs] produces a sanitized copy of the OCI
//     spec suitable for the Linux GCS, stripping unsupported fields and
//     applying safe defaults.
//
// The resulting [container.ResourcePlan] and spec are handed back to the
// controller, which commits them to the VM and sends the final container
// document to GCS for container creation. Because reservations are tracked as
// individual IDs (not blanket closers), the controller can selectively release
// or transfer each resource during live migration save/restore.
//
// The controller's Create method drives the overall flow:
//
//	// 1. Reserve resources (layers, mounts, devices) and rewrite the spec.
//	reservations := lcow.ReserveAll(ctx, scsiReserver, plan9Reserver, vpciReserver, spec, cfg)
//
//	// 2. Generate the sanitized OCI spec for the GCS.
//	doc := generateContainerDocument(spec, reservations)  // calls lcow.GenerateSpecs
//
//	// 3. Allocate (attach/mount) the reserved resources into the VM.
//	allocateContainerResources(reservations)
//
//	// 4. Send the document to the GCS to create the container.
//	guestMgr.CreateContainer(doc)
//
// [container.Controller]: github.com/Microsoft/hcsshim/internal/controller/container
package lcow
