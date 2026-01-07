//go:build linux

package spec

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Microsoft/hcsshim/internal/guestpath"
	"github.com/Microsoft/hcsshim/pkg/annotations"
	"github.com/opencontainers/cgroups/devices/config"
	oci "github.com/opencontainers/runtime-spec/specs-go"
)

// setupMockRootfs creates a temporary rootfs directory structure with /etc/passwd and /etc/group files.
func setupMockRootfs(t *testing.T) string {
	t.Helper()
	rootDir := t.TempDir()
	etcDir := filepath.Join(rootDir, "etc")
	if err := os.MkdirAll(etcDir, 0755); err != nil {
		t.Fatalf("failed to create etc dir: %v", err)
	}

	// Create /etc/passwd
	// Format: name:password:uid:gid:gecos:directory:shell
	passwdContent := `root:x:0:0:root:/root:/bin/bash
testuser:x:1000:1000:Test User:/home/testuser:/bin/sh
no-group-user:x:1001:9999::/home/nogroup:/bin/sh
overflow-uid:x:4294967296:1000:::/bin/sh
`
	if err := os.WriteFile(filepath.Join(etcDir, "passwd"), []byte(passwdContent), 0644); err != nil {
		t.Fatalf("failed to write passwd: %v", err)
	}

	// Create /etc/group
	// Format: group_name:password:GID:user_list
	groupContent := `root:x:0:
testgroup:x:1000:
othergroup:x:1002:
overflow-gid:x:1003:
`
	if err := os.WriteFile(filepath.Join(etcDir, "group"), []byte(groupContent), 0644); err != nil {
		t.Fatalf("failed to write group: %v", err)
	}

	return rootDir
}

// TestNetworkingMountPaths verifies the networking mount paths are as expected.
func TestNetworkingMountPaths(t *testing.T) {
	paths := networkingMountPaths()
	expected := []string{"/etc/hostname", "/etc/hosts", "/etc/resolv.conf"}

	if len(paths) != len(expected) {
		t.Errorf("expected %d paths, got %d", len(expected), len(paths))
	}

	for i, p := range paths {
		if p != expected[i] {
			t.Errorf("index %d: expected %s, got %s", i, expected[i], p)
		}
	}
}

// TestGenerateWorkloadContainerNetworkMounts tests the generation of network-related mounts for a workload container.
func TestGenerateWorkloadContainerNetworkMounts(t *testing.T) {
	sandboxID := "sandbox-123"

	tests := []struct {
		// name of the test case
		name string
		// OCI spec input
		spec *oci.Spec
		// expected number of mounts generated
		expectedCount int
		// optional function to check mount options
		checkOpts func([]oci.Mount) error
	}{
		{
			name:          "Basic generation",
			spec:          &oci.Spec{Root: &oci.Root{Readonly: false}},
			expectedCount: 3,
			checkOpts: func(mounts []oci.Mount) error {
				for _, m := range mounts {
					if len(m.Options) != 1 || m.Options[0] != "bind" {
						return fmt.Errorf("expected options [bind], got %v for %s", m.Options, m.Destination)
					}
				}
				return nil
			},
		},
		{
			name:          "Root Readonly",
			spec:          &oci.Spec{Root: &oci.Root{Readonly: true}},
			expectedCount: 3,
			checkOpts: func(mounts []oci.Mount) error {
				for _, m := range mounts {
					foundRo := false
					for _, opt := range m.Options {
						if opt == "ro" {
							foundRo = true
						}
					}
					if !foundRo {
						return fmt.Errorf("expected 'ro' option for mount %s", m.Destination)
					}
				}
				return nil
			},
		},
		{
			name: "Skip existing mounts",
			spec: &oci.Spec{
				Mounts: []oci.Mount{
					{Destination: "/etc/hostname", Type: "bind"},
				},
				Root: &oci.Root{},
			},
			expectedCount: 2, // Should generate hosts and resolv.conf, skip hostname
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := GenerateWorkloadContainerNetworkMounts(sandboxID, tc.spec)
			if len(res) != tc.expectedCount {
				t.Errorf("expected %d mounts, got %d", tc.expectedCount, len(res))
			}
			if tc.checkOpts != nil {
				if err := tc.checkOpts(res); err != nil {
					t.Error(err)
				}
			}

			// Verify Source Path Structure
			for _, m := range res {
				if !strings.HasPrefix(m.Source, guestpath.LCOWRootPrefixInUVM) {
					t.Errorf("mount source %s does not contain prefix", m.Source)
				}
			}
		})
	}
}

// TestSandboxPathHelpers tests the sandbox path helper functions with full path validation.
func TestSandboxPathHelpers(t *testing.T) {
	sid := "test-id"

	// 1. Validate SandboxRootDir
	// Expected: <LCOWRootPrefixInUVM>/<sandboxID>
	expectedRoot := filepath.Join(guestpath.LCOWRootPrefixInUVM, sid)
	if got := SandboxRootDir(sid); got != expectedRoot {
		t.Errorf("SandboxRootDir mismatch:\nExpected: %s\nGot:      %s", expectedRoot, got)
	}

	// 2. Validate SandboxMountsDir
	// Expected: <Root>/sandboxMounts
	expectedMounts := filepath.Join(expectedRoot, "sandboxMounts")
	if got := SandboxMountsDir(sid); got != expectedMounts {
		t.Errorf("SandboxMountsDir mismatch:\nExpected: %s\nGot:      %s", expectedMounts, got)
	}

	// 3. Validate SandboxTmpfsMountsDir
	// Expected: <Root>/sandboxTmpfsMounts
	expectedTmpfs := filepath.Join(expectedRoot, "sandboxTmpfsMounts")
	if got := SandboxTmpfsMountsDir(sid); got != expectedTmpfs {
		t.Errorf("SandboxTmpfsMountsDir mismatch:\nExpected: %s\nGot:      %s", expectedTmpfs, got)
	}

	// 4. Validate HugePagesMountsDir
	// Expected: <Root>/hugepages
	expectedHugePages := filepath.Join(expectedRoot, "hugepages")
	if got := HugePagesMountsDir(sid); got != expectedHugePages {
		t.Errorf("HugePagesMountsDir mismatch:\nExpected: %s\nGot:      %s", expectedHugePages, got)
	}

	// 5. Validate SandboxLogsDir
	// Expected: <Root>/logs
	expectedLogs := filepath.Join(expectedRoot, "logs")
	if got := SandboxLogsDir(sid); got != expectedLogs {
		t.Errorf("SandboxLogsDir mismatch:\nExpected: %s\nGot:      %s", expectedLogs, got)
	}

	// 6. Validate SandboxMountSource
	// Logic: <MountsDir> + (path stripped of SandboxMountPrefix)
	testPath := filepath.Join(guestpath.SandboxMountPrefix, "some/path")
	// The implementation trims the prefix, then Joins.
	// We mimic that exact behavior to verify the full resulting path.
	relative := strings.TrimPrefix(testPath, guestpath.SandboxMountPrefix)
	expectedSource := filepath.Join(expectedMounts, relative)

	if got := SandboxMountSource(sid, testPath); got != expectedSource {
		t.Errorf("SandboxMountSource mismatch:\nExpected: %s\nGot:      %s", expectedSource, got)
	}

	// 7. Validate SandboxTmpfsMountSource
	// Logic: <TmpfsMountsDir> + (path stripped of SandboxTmpfsMountPrefix)
	testTmpfsPath := filepath.Join(guestpath.SandboxTmpfsMountPrefix, "tmp/file")
	relativeTmpfs := strings.TrimPrefix(testTmpfsPath, guestpath.SandboxTmpfsMountPrefix)
	expectedTmpfsSource := filepath.Join(expectedTmpfs, relativeTmpfs)

	if got := SandboxTmpfsMountSource(sid, testTmpfsPath); got != expectedTmpfsSource {
		t.Errorf("SandboxTmpfsMountSource mismatch:\nExpected: %s\nGot:      %s", expectedTmpfsSource, got)
	}
}

// TestGetNetworkNamespaceID tests the extraction of network namespace ID from OCI spec.
func TestGetNetworkNamespaceID(t *testing.T) {
	tests := []struct {
		spec     *oci.Spec
		expected string
	}{
		{spec: &oci.Spec{}, expected: ""},
		{spec: &oci.Spec{Windows: &oci.Windows{}}, expected: ""},
		{spec: &oci.Spec{Windows: &oci.Windows{Network: &oci.WindowsNetwork{NetworkNamespace: "ID-123"}}}, expected: "id-123"},
	}

	for _, tc := range tests {
		if res := GetNetworkNamespaceID(tc.spec); res != tc.expected {
			t.Errorf("expected '%s', got '%s'", tc.expected, res)
		}
	}
}

// TestSetCoreRLimit tests the SetCoreRLimit function with various inputs.
func TestSetCoreRLimit(t *testing.T) {
	tests := []struct {
		input       string
		shouldError bool
		check       func(*oci.Spec)
	}{
		{
			input:       "1024;2048",
			shouldError: false,
			check: func(s *oci.Spec) {
				if len(s.Process.Rlimits) != 1 {
					t.Error("rlimit not appended")
					return
				}
				r := s.Process.Rlimits[0]
				if r.Type != "RLIMIT_CORE" || r.Soft != 1024 || r.Hard != 2048 {
					t.Errorf("mismatch rlimit values: %+v", r)
				}
			},
		},
		{input: "100", shouldError: true},         // Missing delimiter
		{input: "100;200;300", shouldError: true}, // Too many values
		{input: "foo;200", shouldError: true},     // Invalid soft
		{input: "100;bar", shouldError: true},     // Invalid hard
	}

	for _, tc := range tests {
		spec := &oci.Spec{}
		err := SetCoreRLimit(spec, tc.input)
		if tc.shouldError && err == nil {
			t.Errorf("expected error for input '%s', got nil", tc.input)
		}
		if !tc.shouldError && err != nil {
			t.Errorf("unexpected error for input '%s': %v", tc.input, err)
		}
		if !tc.shouldError && tc.check != nil {
			tc.check(spec)
		}
	}
}

// TestSetUserStr_And_ParseUserStr tests the SetUserStr and ParseUserStr functions with various user string formats.
func TestSetUserStr_And_ParseUserStr(t *testing.T) {
	rootDir := setupMockRootfs(t)

	tests := []struct {
		name          string
		userStr       string
		expectError   bool
		expectedUID   uint32
		expectedGID   uint32
		errorContains string
	}{
		// --- Happy Paths ---
		{
			name:        "Valid Username",
			userStr:     "testuser",
			expectedUID: 1000,
			expectedGID: 1000,
		},
		{
			name:        "Valid UID (exists in passwd)",
			userStr:     "1000",
			expectedUID: 1000,
			expectedGID: 1000,
		},
		{
			name:        "Valid UID (does not exist, fallback)",
			userStr:     "5000",
			expectedUID: 5000,
			expectedGID: 0,
		},
		{
			name:        "User:Group Names",
			userStr:     "testuser:testgroup",
			expectedUID: 1000,
			expectedGID: 1000,
		},
		{
			name:        "User:Group Mixed (User:GID)",
			userStr:     "testuser:1002",
			expectedUID: 1000,
			expectedGID: 1002,
		},
		{
			name:        "UID:GID Numeric",
			userStr:     "2000:2000",
			expectedUID: 2000,
			expectedGID: 2000,
		},
		{
			name:        "Root User",
			userStr:     "root",
			expectedUID: 0,
			expectedGID: 0,
		},

		// --- Negative Cases ---
		{
			name:          "Invalid format",
			userStr:       "user:group:extra",
			expectError:   true,
			errorContains: "invalid userstr",
		},
		{
			name:          "Unknown Username",
			userStr:       "nonexistent",
			expectError:   true,
			errorContains: "failed to find user",
		},
		{
			name:          "Unknown Group Name",
			userStr:       "testuser:badgroup",
			expectError:   true,
			errorContains: "failed to find group",
		},
		{
			name:          "UID overflow uint32",
			userStr:       "4294967296", // MaxUint32 + 1
			expectError:   true,
			errorContains: "exceeds uint32 bounds",
		},
		{
			name:          "GID overflow uint32",
			userStr:       "1000:4294967296",
			expectError:   true,
			errorContains: "exceeds uint32 bounds",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := &oci.Spec{Root: &oci.Root{Path: rootDir}}
			err := SetUserStr(spec, tc.userStr)

			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error containing '%s', got nil", tc.errorContains)
				}
				if !strings.Contains(err.Error(), tc.errorContains) {
					t.Errorf("expected error to contain '%s', got '%v'", tc.errorContains, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if spec.Process.User.UID != tc.expectedUID {
					t.Errorf("UID mismatch. Expected %d, got %d", tc.expectedUID, spec.Process.User.UID)
				}
				if spec.Process.User.GID != tc.expectedGID {
					t.Errorf("GID mismatch. Expected %d, got %d", tc.expectedGID, spec.Process.User.GID)
				}
			}
		})
	}
}

// TestApplyAnnotationsToSpec_DevShm tests the /dev/shm size adjustment logic in ApplyAnnotationsToSpec.
func TestApplyAnnotationsToSpec_DevShm(t *testing.T) {
	tests := []struct {
		name          string
		annotations   map[string]string
		initialMounts []oci.Mount
		expectError   bool
		check         func(*oci.Spec) error
	}{
		{
			name:        "Custom DevShm Size",
			annotations: map[string]string{annotations.LCOWDevShmSizeInKb: "1024"},
			initialMounts: []oci.Mount{
				{Destination: "/dev/shm", Type: "tmpfs", Options: []string{"size=64k"}},
			},
			expectError: false,
			check: func(s *oci.Spec) error {
				for _, m := range s.Mounts {
					if m.Destination == "/dev/shm" {
						for _, o := range m.Options {
							if o == "size=1024k" {
								return nil
							}
						}
						return fmt.Errorf("size option not found in %v", m.Options)
					}
				}
				return fmt.Errorf("/dev/shm mount not found")
			},
		},
		{
			name:        "Invalid DevShm Size (Non-numeric)",
			annotations: map[string]string{annotations.LCOWDevShmSizeInKb: "invalid"},
			expectError: true,
		},
		{
			name:        "Invalid DevShm Size (Zero)",
			annotations: map[string]string{annotations.LCOWDevShmSizeInKb: "0"},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := &oci.Spec{
				Annotations: tc.annotations,
				Mounts:      tc.initialMounts,
				Linux:       &oci.Linux{}, // prevents nil panic in other parts of function
			}

			err := ApplyAnnotationsToSpec(context.Background(), spec)

			if tc.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if tc.check != nil {
					if err := tc.check(spec); err != nil {
						t.Error(err)
					}
				}
			}
		})
	}
}

// TestApplyAnnotationsToSpec_Devices tests the device mapping logic in ApplyAnnotationsToSpec.
func TestApplyAnnotationsToSpec_Devices(t *testing.T) {
	// 1. Setup Mocking
	// Store original functions to restore them after tests
	origHostDevices := devicesHostDevicesFn
	origDeviceFromPath := devicesDeviceFromPathFn

	t.Cleanup(func() {
		devicesHostDevicesFn = origHostDevices
		devicesDeviceFromPathFn = origDeviceFromPath
	})

	// Define dummy devices for mocking using the new config.Device struct
	mockHostDev1 := &config.Device{
		Rule: config.Rule{
			Type:        'c',
			Major:       10,
			Minor:       200,
			Permissions: "rwm",
		},
		Path: "/dev/mock1",
		Uid:  0,
		Gid:  0,
	}
	mockHostDev2 := &config.Device{
		Rule: config.Rule{
			Type:        'b',
			Major:       8,
			Minor:       1,
			Permissions: "r",
		},
		Path: "/dev/mock2",
		Uid:  1000,
		Gid:  1000,
	}

	// 2. Define Tests
	tests := []struct {
		name               string
		annotations        map[string]string
		initialLinux       *oci.Linux
		mockHostDevices    func() ([]*config.Device, error)
		mockDeviceFromPath func(string, string) (*config.Device, error)
		expectError        bool
		check              func(*oci.Spec) error
	}{
		{
			name: "Privileged Container - Success",
			annotations: map[string]string{
				annotations.LCOWPrivileged: "true",
			},
			initialLinux: &oci.Linux{
				Resources: &oci.LinuxResources{},
			},
			mockHostDevices: func() ([]*config.Device, error) {
				return []*config.Device{mockHostDev1, mockHostDev2}, nil
			},
			expectError: false,
			check: func(s *oci.Spec) error {
				// Check 1: All host devices added to Linux.Devices
				if len(s.Linux.Devices) != 2 {
					return fmt.Errorf("expected 2 devices, got %d", len(s.Linux.Devices))
				}
				// Verify one device content
				if s.Linux.Devices[0].Path != mockHostDev1.Path {
					return fmt.Errorf("expected device path %s, got %s", mockHostDev1.Path, s.Linux.Devices[0].Path)
				}

				// Check 2: Cgroup access set to Allow All (rwm)
				if len(s.Linux.Resources.Devices) == 0 {
					return fmt.Errorf("expected resources.devices to be set")
				}
				cgroup := s.Linux.Resources.Devices[0]
				if !cgroup.Allow || cgroup.Access != "rwm" {
					return fmt.Errorf("expected allow=true access=rwm, got allow=%v access=%s", cgroup.Allow, cgroup.Access)
				}
				return nil
			},
		},
		{
			name: "Privileged Container - HostDevices Error",
			annotations: map[string]string{
				annotations.LCOWPrivileged: "true",
			},
			initialLinux: &oci.Linux{Resources: &oci.LinuxResources{}},
			mockHostDevices: func() ([]*config.Device, error) {
				return nil, fmt.Errorf("failed to list devices")
			},
			expectError: true,
		},
		{
			name:        "Regular Container - Specific Device Mapping",
			annotations: nil, // Not privileged
			initialLinux: &oci.Linux{
				Devices: []oci.LinuxDevice{
					{Path: "/dev/mock1"}, // User requests this device
				},
				Resources: &oci.LinuxResources{},
			},
			mockDeviceFromPath: func(path, perms string) (*config.Device, error) {
				if path == "/dev/mock1" {
					return mockHostDev1, nil
				}
				return nil, fmt.Errorf("device not found")
			},
			expectError: false,
			check: func(s *oci.Spec) error {
				// Check 1: Device details updated from host
				if len(s.Linux.Devices) != 1 {
					return fmt.Errorf("expected 1 device, got %d", len(s.Linux.Devices))
				}
				d := s.Linux.Devices[0]
				if d.Major != mockHostDev1.Major || d.Minor != mockHostDev1.Minor {
					return fmt.Errorf("device major/minor mismatch. Expected %d:%d, got %d:%d",
						mockHostDev1.Major, mockHostDev1.Minor, d.Major, d.Minor)
				}

				// Check 2: Cgroup specifically added for this device
				if len(s.Linux.Resources.Devices) != 1 {
					return fmt.Errorf("expected 1 cgroup rule, got %d", len(s.Linux.Resources.Devices))
				}
				cg := s.Linux.Resources.Devices[0]
				if cg.Access != string(mockHostDev1.Permissions) {
					return fmt.Errorf("expected cgroup access %s, got %s", mockHostDev1.Permissions, cg.Access)
				}
				return nil
			},
		},
		{
			name:        "Regular Container - DeviceFromPath Error",
			annotations: nil,
			initialLinux: &oci.Linux{
				Devices:   []oci.LinuxDevice{{Path: "/dev/missing"}},
				Resources: &oci.LinuxResources{},
			},
			mockDeviceFromPath: func(path, perms string) (*config.Device, error) {
				return nil, fmt.Errorf("no such device")
			},
			expectError: true,
		},
		{
			name: "Invalid Annotation Value (Parsing Error Logged, treated as false)",
			annotations: map[string]string{
				annotations.LCOWPrivileged: "not-a-bool",
			},
			initialLinux: &oci.Linux{
				Devices:   []oci.LinuxDevice{{Path: "/dev/mock1"}},
				Resources: &oci.LinuxResources{},
			},
			mockDeviceFromPath: func(path, perms string) (*config.Device, error) {
				return mockHostDev1, nil
			},
			expectError: false,
			check: func(s *oci.Spec) error {
				// Should behave like non-privileged (fallback)
				if len(s.Linux.Devices) != 1 {
					return fmt.Errorf("expected 1 device (fallback behavior), got %d", len(s.Linux.Devices))
				}
				return nil
			},
		},
	}

	// 3. Execution Loop
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Apply mocks for this specific test case
			if tc.mockHostDevices != nil {
				devicesHostDevicesFn = tc.mockHostDevices
			}
			if tc.mockDeviceFromPath != nil {
				devicesDeviceFromPathFn = tc.mockDeviceFromPath
			}

			spec := &oci.Spec{
				Annotations: tc.annotations,
				Linux:       tc.initialLinux,
			}

			err := ApplyAnnotationsToSpec(context.Background(), spec)

			if tc.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if tc.check != nil {
					if err := tc.check(spec); err != nil {
						t.Error(err)
					}
				}
			}
		})
	}
}

// TestDevShmMountWithSize tests the devShmMountWithSize function for correct size parsing and mount creation.
func TestDevShmMountWithSize(t *testing.T) {
	// Positive case
	mt, err := devShmMountWithSize("1024")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	foundSize := false
	for _, opt := range mt.Options {
		if opt == "size=1024k" {
			foundSize = true
		}
	}
	if !foundSize {
		t.Errorf("did not find size=1024k in options: %v", mt.Options)
	}

	// Negative cases
	_, err = devShmMountWithSize("abc")
	if err == nil {
		t.Error("expected error for non-integer size")
	}

	_, err = devShmMountWithSize("0")
	if err == nil {
		t.Error("expected error for zero size")
	}
}

// TestOutOfUint32Bounds tests the OutOfUint32Bounds function with various inputs.
func TestOutOfUint32Bounds(t *testing.T) {
	if OutOfUint32Bounds(100) {
		t.Error("100 should be within bounds")
	}
	if !OutOfUint32Bounds(-1) {
		t.Error("-1 should be out of bounds")
	}
	if !OutOfUint32Bounds(math.MaxInt) {
		// MaxInt is usually much larger than MaxUint32 on 64-bit systems
		// On 32-bit systems MaxInt == MaxUint32/2 approx, so this test depends on arch.
		// Let's test boundary explicitly based on logic.
		if uint64(math.MaxInt) > uint64(math.MaxUint32) {
			// This block runs on 64-bit systems
			t.Errorf("MaxInt %d should be out of uint32 bounds", math.MaxInt)
		} else {
			t.Skip("Skipping MaxInt test on 32-bit arch")
		}
	}
}

// TestRemoveMount tests the removeMount function to ensure it correctly removes a mount by destination.
func TestRemoveMount(t *testing.T) {
	mounts := []oci.Mount{
		{Destination: "/keep"},
		{Destination: "/remove"},
		{Destination: "/keep/2"},
	}

	res := removeMount("/remove", mounts)

	if len(res) != 2 {
		t.Errorf("expected 2 mounts, got %d", len(res))
	}
	for _, m := range res {
		if m.Destination == "/remove" {
			t.Error("found removed mount")
		}
	}
}
