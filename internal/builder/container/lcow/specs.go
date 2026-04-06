//go:build windows && lcow

package lcow

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Microsoft/hcsshim/internal/oci"
	"github.com/Microsoft/hcsshim/pkg/annotations"

	"github.com/opencontainers/runtime-spec/specs-go"
)

// GenerateSpecs produces a deep copy of oci specs tailored for an LCOW container,
// stripping unsupported fields and applying safe defaults.
func GenerateSpecs(ctx context.Context, origSpec *specs.Spec) (*specs.Spec, error) {
	if origSpec.Linux == nil {
		return nil, fmt.Errorf("linux section must be present for lcow container")
	}

	// Create a deep copy of the original OCI specs.
	spec, err := deepCopySpec(origSpec)
	if err != nil {
		return nil, err
	}

	// Preserve only the network namespace and assigned devices from the Windows section.
	spec.Windows = extractWindowsFields(origSpec)

	// Hooks are not supported in the guest; they should be executed on the host.
	spec.Hooks = nil

	// Sanitize and apply safe defaults for Linux fields.
	sanitizeLinuxCPUDefaults(spec)

	// Clear any unsupported Linux resources from the spec.
	clearUnsupportedLinuxResources(spec)

	// Disable seccomp filtering for privileged containers.
	isPrivileged := oci.ParseAnnotationsBool(ctx, spec.Annotations, annotations.LCOWPrivileged, false)
	if isPrivileged {
		spec.Linux.Seccomp = nil
	}

	return spec, nil
}

// deepCopySpec performs a deep copy of the spec via JSON round-trip so mutations
// do not affect the caller's copy.
func deepCopySpec(origSpec *specs.Spec) (*specs.Spec, error) {
	specJSON, err := json.Marshal(origSpec)
	if err != nil {
		return nil, fmt.Errorf("marshal spec: %w", err)
	}
	spec := &specs.Spec{}
	if err := json.Unmarshal(specJSON, spec); err != nil {
		return nil, fmt.Errorf("unmarshal spec: %w", err)
	}
	return spec, nil
}

// extractWindowsFields extracts only the Windows fields relevant for LCOW:
// the network namespace and any assigned vPCI / GPU devices.
func extractWindowsFields(origSpec *specs.Spec) *specs.Windows {
	if origSpec.Windows == nil {
		return nil
	}

	var windows *specs.Windows

	// Preserve the network namespace so the container joins the correct HNS network.
	if origSpec.Windows.Network != nil && origSpec.Windows.Network.NetworkNamespace != "" {
		windows = &specs.Windows{
			Network: &specs.WindowsNetwork{
				NetworkNamespace: origSpec.Windows.Network.NetworkNamespace,
			},
		}
	}

	// Carry over any assigned vPCI / GPU devices.
	if origSpec.Windows.Devices != nil {
		if windows == nil {
			windows = &specs.Windows{}
		}
		windows.Devices = origSpec.Windows.Devices
	}

	return windows
}

// sanitizeLinuxCPUDefaults applies safe CPU defaults when the values are explicitly zeroed.
func sanitizeLinuxCPUDefaults(spec *specs.Spec) {
	if spec.Linux.Resources == nil || spec.Linux.Resources.CPU == nil {
		return
	}

	cpuResources := spec.Linux.Resources.CPU
	if cpuResources.Period != nil && *cpuResources.Period == 0 {
		*cpuResources.Period = 100000 // Default CFS period in microseconds.
	}
	if cpuResources.Quota != nil && *cpuResources.Quota == 0 {
		*cpuResources.Quota = -1 // Unlimited CPU quota.
	}
}

// clearUnsupportedLinuxResources removes resource types the GCS does not support
// or manages on its own.
func clearUnsupportedLinuxResources(spec *specs.Spec) {
	// GCS controls the cgroup hierarchy internally.
	spec.Linux.CgroupsPath = ""

	if spec.Linux.Resources != nil {
		spec.Linux.Resources.Devices = nil
		spec.Linux.Resources.Pids = nil
		spec.Linux.Resources.BlockIO = nil
		spec.Linux.Resources.HugepageLimits = nil
		spec.Linux.Resources.Network = nil
	}
}
