//go:build windows && lcow

package lcow

import (
	"testing"

	"github.com/Microsoft/hcsshim/pkg/annotations"
	"github.com/opencontainers/runtime-spec/specs-go"
)

// ─────────────────────────────────────────────────────────────────────────────
// GenerateSpecs — nil Linux section
// ─────────────────────────────────────────────────────────────────────────────

// TestGenerateSpecs_NilLinux verifies that a spec without a Linux section
// returns an error.
func TestGenerateSpecs_NilLinux(t *testing.T) {
	t.Parallel()

	_, err := GenerateSpecs(t.Context(), &specs.Spec{})
	if err == nil {
		t.Fatal("expected error for nil Linux section")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GenerateSpecs — hooks are stripped
// ─────────────────────────────────────────────────────────────────────────────

// TestGenerateSpecs_HooksStripped verifies that OCI hooks are removed from the
// generated spec.
func TestGenerateSpecs_HooksStripped(t *testing.T) {
	t.Parallel()

	origSpec := &specs.Spec{
		Linux: &specs.Linux{},
		Hooks: &specs.Hooks{
			CreateRuntime: []specs.Hook{{Path: "/bin/prehook"}},
		},
	}

	spec, err := GenerateSpecs(t.Context(), origSpec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.Hooks != nil {
		t.Error("expected hooks to be nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GenerateSpecs — deep copy does not mutate original
// ─────────────────────────────────────────────────────────────────────────────

// TestGenerateSpecs_DeepCopy verifies that the returned spec is a deep copy
// and mutations to it do not affect the original.
func TestGenerateSpecs_DeepCopy(t *testing.T) {
	t.Parallel()

	origSpec := &specs.Spec{
		Linux:   &specs.Linux{},
		Process: &specs.Process{Args: []string{"sh"}},
	}

	spec, err := GenerateSpecs(t.Context(), origSpec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mutate the returned spec.
	spec.Process.Args = append(spec.Process.Args, "-c", "exit")

	// The original must remain unchanged.
	if len(origSpec.Process.Args) != 1 {
		t.Errorf("original spec mutated: args = %v", origSpec.Process.Args)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GenerateSpecs — privileged container clears seccomp
// ─────────────────────────────────────────────────────────────────────────────

// TestGenerateSpecs_PrivilegedClearsSeccomp verifies that when the privileged
// annotation is set, the seccomp profile is cleared.
func TestGenerateSpecs_PrivilegedClearsSeccomp(t *testing.T) {
	t.Parallel()

	origSpec := &specs.Spec{
		Linux: &specs.Linux{
			Seccomp: &specs.LinuxSeccomp{DefaultAction: specs.ActErrno},
		},
		Annotations: map[string]string{
			annotations.LCOWPrivileged: "true",
		},
	}

	spec, err := GenerateSpecs(t.Context(), origSpec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.Linux.Seccomp != nil {
		t.Error("expected seccomp to be nil for privileged container")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GenerateSpecs — non-privileged preserves seccomp
// ─────────────────────────────────────────────────────────────────────────────

// TestGenerateSpecs_NonPrivilegedPreservesSeccomp verifies that the seccomp
// profile is preserved when the container is not privileged.
func TestGenerateSpecs_NonPrivilegedPreservesSeccomp(t *testing.T) {
	t.Parallel()

	origSpec := &specs.Spec{
		Linux: &specs.Linux{
			Seccomp: &specs.LinuxSeccomp{DefaultAction: specs.ActErrno},
		},
	}

	spec, err := GenerateSpecs(t.Context(), origSpec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.Linux.Seccomp == nil {
		t.Error("expected seccomp to be preserved for non-privileged container")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// extractWindowsFields
// ─────────────────────────────────────────────────────────────────────────────

// TestExtractWindowsFields verifies that only the network namespace and
// assigned devices are preserved from the Windows section.
func TestExtractWindowsFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		input         *specs.Spec
		wantNil       bool
		wantNamespace string
		wantDeviceIDs []string
	}{
		{
			name:    "nil Windows",
			input:   &specs.Spec{},
			wantNil: true,
		},
		{
			name: "network namespace only",
			input: &specs.Spec{
				Windows: &specs.Windows{
					Network: &specs.WindowsNetwork{NetworkNamespace: "ns-123"},
				},
			},
			wantNamespace: "ns-123",
		},
		{
			name: "devices only",
			input: &specs.Spec{
				Windows: &specs.Windows{
					Devices: []specs.WindowsDevice{{ID: "dev-1"}},
				},
			},
			wantDeviceIDs: []string{"dev-1"},
		},
		{
			name: "both network and devices",
			input: &specs.Spec{
				Windows: &specs.Windows{
					Network: &specs.WindowsNetwork{NetworkNamespace: "ns-456"},
					Devices: []specs.WindowsDevice{{ID: "dev-2"}},
				},
			},
			wantNamespace: "ns-456",
			wantDeviceIDs: []string{"dev-2"},
		},
		{
			name: "empty network namespace",
			input: &specs.Spec{
				Windows: &specs.Windows{
					Network: &specs.WindowsNetwork{NetworkNamespace: ""},
				},
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractWindowsFields(tt.input)

			if tt.wantNil {
				if result != nil {
					t.Fatalf("expected nil, got %+v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("expected non-nil Windows")
			}

			// Validate network namespace.
			if tt.wantNamespace != "" {
				if result.Network == nil || result.Network.NetworkNamespace != tt.wantNamespace {
					t.Errorf("expected namespace %q, got %+v", tt.wantNamespace, result.Network)
				}
			} else if result.Network != nil {
				t.Errorf("expected nil network, got %+v", result.Network)
			}

			// Validate devices.
			if len(tt.wantDeviceIDs) != len(result.Devices) {
				t.Fatalf("expected %d devices, got %d", len(tt.wantDeviceIDs), len(result.Devices))
			}
			for i, wantID := range tt.wantDeviceIDs {
				if result.Devices[i].ID != wantID {
					t.Errorf("device[%d]: expected ID %q, got %q", i, wantID, result.Devices[i].ID)
				}
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// sanitizeLinuxCPUDefaults
// ─────────────────────────────────────────────────────────────────────────────

// TestSanitizeLinuxCPUDefaults verifies that zero-valued CPU period and quota
// are replaced with safe defaults, while non-zero values and nil fields are
// left unchanged.
func TestSanitizeLinuxCPUDefaults(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		resources  *specs.LinuxResources
		wantPeriod *uint64
		wantQuota  *int64
	}{
		{
			name:      "nil Resources",
			resources: nil,
		},
		{
			name:      "nil CPU",
			resources: &specs.LinuxResources{},
		},
		{
			name: "zero Period and Quota get defaults",
			resources: func() *specs.LinuxResources {
				var period uint64
				var quota int64
				return &specs.LinuxResources{
					CPU: &specs.LinuxCPU{Period: &period, Quota: &quota},
				}
			}(),
			wantPeriod: func() *uint64 { v := uint64(100000); return &v }(),
			wantQuota:  func() *int64 { v := int64(-1); return &v }(),
		},
		{
			name: "non-zero values unchanged",
			resources: func() *specs.LinuxResources {
				period := uint64(50000)
				quota := int64(25000)
				return &specs.LinuxResources{
					CPU: &specs.LinuxCPU{Period: &period, Quota: &quota},
				}
			}(),
			wantPeriod: func() *uint64 { v := uint64(50000); return &v }(),
			wantQuota:  func() *int64 { v := int64(25000); return &v }(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := &specs.Spec{Linux: &specs.Linux{Resources: tt.resources}}

			sanitizeLinuxCPUDefaults(spec)

			// For nil Resources or nil CPU, just verify no panic.
			if tt.wantPeriod == nil && tt.wantQuota == nil {
				return
			}

			cpu := spec.Linux.Resources.CPU
			if tt.wantPeriod != nil && *cpu.Period != *tt.wantPeriod {
				t.Errorf("expected Period %d, got %d", *tt.wantPeriod, *cpu.Period)
			}
			if tt.wantQuota != nil && *cpu.Quota != *tt.wantQuota {
				t.Errorf("expected Quota %d, got %d", *tt.wantQuota, *cpu.Quota)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// clearUnsupportedLinuxResources
// ─────────────────────────────────────────────────────────────────────────────

// TestClearUnsupportedResources verifies that unsupported resource types are
// cleared and the cgroups path is emptied.
func TestClearUnsupportedResources(t *testing.T) {
	t.Parallel()

	shares := uint64(512)

	spec := &specs.Spec{
		Linux: &specs.Linux{
			CgroupsPath: "/sys/fs/cgroup/test",
			Resources: &specs.LinuxResources{
				Devices:        []specs.LinuxDeviceCgroup{{Allow: true}},
				Pids:           &specs.LinuxPids{Limit: 100},
				BlockIO:        &specs.LinuxBlockIO{},
				HugepageLimits: []specs.LinuxHugepageLimit{{Pagesize: "2MB", Limit: 1024}},
				Network:        &specs.LinuxNetwork{},
				// CPU and Memory should be preserved (not cleared).
				CPU:    &specs.LinuxCPU{Shares: &shares},
				Memory: &specs.LinuxMemory{},
			},
		},
	}

	clearUnsupportedLinuxResources(spec)

	if spec.Linux.CgroupsPath != "" {
		t.Errorf("expected empty cgroups path, got %q", spec.Linux.CgroupsPath)
	}
	if spec.Linux.Resources.Devices != nil {
		t.Error("expected Devices to be nil")
	}
	if spec.Linux.Resources.Pids != nil {
		t.Error("expected Pids to be nil")
	}
	if spec.Linux.Resources.BlockIO != nil {
		t.Error("expected BlockIO to be nil")
	}
	if spec.Linux.Resources.HugepageLimits != nil {
		t.Error("expected HugepageLimits to be nil")
	}
	if spec.Linux.Resources.Network != nil {
		t.Error("expected Network to be nil")
	}
	// CPU and Memory must survive.
	if spec.Linux.Resources.CPU == nil {
		t.Error("expected CPU to be preserved")
	}
	if spec.Linux.Resources.Memory == nil {
		t.Error("expected Memory to be preserved")
	}
}

// TestClearUnsupportedResources_NilResources verifies that nil Resources does
// not panic and the cgroups path is still cleared.
func TestClearUnsupportedResources_NilResources(t *testing.T) {
	t.Parallel()

	spec := &specs.Spec{Linux: &specs.Linux{CgroupsPath: "/test"}}

	clearUnsupportedLinuxResources(spec)

	if spec.Linux.CgroupsPath != "" {
		t.Errorf("expected empty cgroups path, got %q", spec.Linux.CgroupsPath)
	}
}
