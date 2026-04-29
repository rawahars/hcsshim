//go:build windows && lcow

package lcow

import (
	"fmt"
	"strings"

	iannotations "github.com/Microsoft/hcsshim/internal/annotations"
	shimannotations "github.com/Microsoft/hcsshim/pkg/annotations"
)

// vmAnnotationPrefix scopes the live-migration policy check to UVM-shape
// annotations. Anything under this prefix that is not in one of the two
// allow-lists below is rejected when [shimannotations.LiveMigrationAllowed]
// is set on the sandbox.
const vmAnnotationPrefix = "io.microsoft.virtualmachine"

// liveMigrationAllowAnyVMAnnotations is the set of UVM-prefixed annotations
// that may be set to any value when LM is enabled.
var liveMigrationAllowAnyVMAnnotations = map[string]struct{}{
	// Boot/kernel selection: pure host-side knobs that don't change the UVM's
	// migratable shape.
	shimannotations.BootFilesRootPath: {},
	// Additional kernel command-line options: applied at boot inside the
	// guest; doesn't bind the UVM to host-physical resources.
	shimannotations.KernelBootOptions: {},
	// CPU/memory shaping.
	shimannotations.AllowOvercommit:        {},
	shimannotations.ProcessorCount:         {},
	shimannotations.ProcessorLimit:         {},
	shimannotations.ProcessorWeight:        {},
	shimannotations.MemorySizeInMB:         {},
	shimannotations.MemoryLowMMIOGapInMB:   {},
	shimannotations.MemoryHighMMIOBaseInMB: {},
	shimannotations.MemoryHighMMIOGapInMB:  {},
	// Storage QoS knobs are pure per-host rate limits;
	shimannotations.StorageQoSIopsMaximum:      {},
	shimannotations.StorageQoSBandwidthMaximum: {},
	// Scratch-disk encryption: a per-UVM crypto setting applied at scratch
	// creation; identical on both sides of a migration.
	shimannotations.LCOWEncryptedScratchDisk: {},
	// In-guest networking policy: applied inside the UVM, host-agnostic.
	iannotations.NetworkingPolicyBasedRouting: {},
	// In-guest chronyd toggle: pure guest-side service control.
	shimannotations.DisableLCOWTimeSyncService: {},
	// Writable overlay dirs are an in-guest tmpfs overlay; they don't bind
	// the UVM to host-backed writable file shares.
	iannotations.WritableOverlayDirs: {},
}

// liveMigrationLockedVMAnnotations is the map of UVM-prefixed annotations that
// may be set under LM, but only to one specific raw value.
var liveMigrationLockedVMAnnotations = map[string]string{
	// LM-capable UVMs must boot from an initrd rootfs.
	shimannotations.PreferredRootFSType: "initrd",
	// LM-capable UVMs must use direct kernel boot.
	shimannotations.KernelDirectBoot: "true",
	// VPCI passthrough binds the UVM to a host-physical device.
	shimannotations.VPCIEnabled: "false",
	// VPMem-backed layers can't be re-attached identically post-migration;
	// VPMemCount=0 forces SCSI for layers.
	shimannotations.VPMemCount: "0",
	// Writable file shares can't be re-mapped identically on the destination
	// host; they must be disabled for an LM-capable UVM.
	shimannotations.DisableWritableFileShares: "true",
}

// validateLiveMigrationAnnotations enforces the live-migration annotation
// policy on a sandbox spec. It must only be invoked when the sandbox has
// opted into live migration via [shimannotations.LiveMigrationAllowed].
//
// Policy:
//
//   - Annotations outside "io.microsoft.virtualmachine.*" scope are allowed.
//   - Annotations matching [iannotations.UVMHyperVSocketConfigPrefix] are
//     always rejected: each entry binds the UVM to a host-side service
//     registration that cannot move with the VM.
//   - Annotations in [liveMigrationAllowAnyVMAnnotations] pass with any value.
//   - Annotations in [liveMigrationLockedVMAnnotations] pass only when their
//     raw value equals the locked value.
//   - All other annotations under "io.microsoft.virtualmachine.*" are rejected
//     (default-deny).
//
// Map iteration order is non-deterministic, so when multiple annotations are
// in violation the returned error names only one of them.
func validateLiveMigrationAnnotations(annotations map[string]string) error {
	for key, val := range annotations {
		// Reject per-GUID HvSocket service-table entries explicitly so the
		// rationale lives next to the policy. They would also be caught by
		// default-deny below.
		if strings.HasPrefix(key, iannotations.UVMHyperVSocketConfigPrefix) {
			return fmt.Errorf("annotation %q is not supported when %s is enabled",
				key, shimannotations.LiveMigrationAllowed)
		}
		if !strings.HasPrefix(key, vmAnnotationPrefix) {
			continue
		}
		if _, ok := liveMigrationAllowAnyVMAnnotations[key]; ok {
			continue
		}
		if want, ok := liveMigrationLockedVMAnnotations[key]; ok {
			if strings.ToLower(val) != want {
				return fmt.Errorf(
					"annotation %q has an unsupported value when %s is enabled: must be %q, got %q",
					key, shimannotations.LiveMigrationAllowed, want, val,
				)
			}
			continue
		}
		return fmt.Errorf("annotation %q is not supported when %s is enabled",
			key, shimannotations.LiveMigrationAllowed)
	}
	return nil
}

// applyLiveMigrationLockedDefaults fills in any annotation in
// [liveMigrationLockedVMAnnotations] that is not already present on the
// sandbox with its required value.
func applyLiveMigrationLockedDefaults(annotations map[string]string) map[string]string {
	if annotations == nil {
		annotations = make(map[string]string, len(liveMigrationLockedVMAnnotations))
	}
	for key, val := range liveMigrationLockedVMAnnotations {
		if _, ok := annotations[key]; !ok {
			annotations[key] = val
		}
	}
	return annotations
}
