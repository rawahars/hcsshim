//go:build windows && lcow

package lcow

import (
	"strings"
	"testing"

	iannotations "github.com/Microsoft/hcsshim/internal/annotations"
	shimannotations "github.com/Microsoft/hcsshim/pkg/annotations"
)

func TestValidateLiveMigrationAnnotations(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		wantErr     bool
		// errSubstr, when wantErr is true, must appear in the returned error.
		errSubstr string
	}{
		// ----- happy paths ------------------------------------------------
		{
			name:        "empty annotations",
			annotations: map[string]string{},
			wantErr:     false,
		},
		{
			name: "non-VM-prefixed annotations are ignored",
			annotations: map[string]string{
				// migration namespace is outside io.microsoft.virtualmachine
				shimannotations.LiveMigrationAllowed: "true",
				// io.microsoft.container.* is outside the VM prefix and is
				// therefore implicitly permitted.
				shimannotations.ContainerProcessDumpLocation: `C:\dumps`,
				// arbitrary user annotations outside the VM namespace
				"io.kubernetes.cri.sandbox-id": "abc123",
				"foo.bar":                      "baz",
			},
			wantErr: false,
		},
		{
			name: "all allow-any annotations accepted with arbitrary values",
			annotations: map[string]string{
				shimannotations.BootFilesRootPath:          `C:\boot`,
				shimannotations.KernelBootOptions:          "console=ttyS0",
				shimannotations.AllowOvercommit:            "false",
				shimannotations.ProcessorCount:             "4",
				shimannotations.ProcessorLimit:             "75000",
				shimannotations.ProcessorWeight:            "200",
				shimannotations.MemorySizeInMB:             "2048",
				shimannotations.MemoryLowMMIOGapInMB:       "128",
				shimannotations.MemoryHighMMIOBaseInMB:     "65536",
				shimannotations.MemoryHighMMIOGapInMB:      "1024",
				shimannotations.StorageQoSIopsMaximum:      "5000",
				shimannotations.StorageQoSBandwidthMaximum: "1000000",
				shimannotations.LCOWEncryptedScratchDisk:   "true",
				shimannotations.DisableLCOWTimeSyncService: "true",
				iannotations.NetworkingPolicyBasedRouting:  "true",
				iannotations.WritableOverlayDirs:           "true",
			},
			wantErr: false,
		},
		{
			name: "locked-value annotations accepted with required values",
			annotations: map[string]string{
				shimannotations.PreferredRootFSType:       "initrd",
				shimannotations.KernelDirectBoot:          "true",
				shimannotations.VPCIEnabled:               "false",
				shimannotations.VPMemCount:                "0",
				shimannotations.DisableWritableFileShares: "true",
			},
			wantErr: false,
		},

		// ----- locked-value violations ------------------------------------
		{
			name: "PreferredRootFSType=vhd is rejected",
			annotations: map[string]string{
				shimannotations.PreferredRootFSType: "vhd",
			},
			wantErr:   true,
			errSubstr: shimannotations.PreferredRootFSType,
		},
		{
			name: "PreferredRootFSType empty is rejected",
			annotations: map[string]string{
				shimannotations.PreferredRootFSType: "",
			},
			wantErr:   true,
			errSubstr: shimannotations.PreferredRootFSType,
		},
		{
			name: "KernelDirectBoot=false is rejected",
			annotations: map[string]string{
				shimannotations.KernelDirectBoot: "false",
			},
			wantErr:   true,
			errSubstr: shimannotations.KernelDirectBoot,
		},
		{
			name: "KernelDirectBoot empty is rejected",
			annotations: map[string]string{
				shimannotations.KernelDirectBoot: "",
			},
			wantErr:   true,
			errSubstr: shimannotations.KernelDirectBoot,
		},
		{
			name: "VPCIEnabled=true is rejected",
			annotations: map[string]string{
				shimannotations.VPCIEnabled: "true",
			},
			wantErr:   true,
			errSubstr: shimannotations.VPCIEnabled,
		},
		{
			name: "DisableWritableFileShares=false is rejected",
			annotations: map[string]string{
				shimannotations.DisableWritableFileShares: "false",
			},
			wantErr:   true,
			errSubstr: shimannotations.DisableWritableFileShares,
		},
		{
			name: "DisableWritableFileShares empty is rejected",
			annotations: map[string]string{
				shimannotations.DisableWritableFileShares: "",
			},
			wantErr:   true,
			errSubstr: shimannotations.DisableWritableFileShares,
		},
		{
			name: "VPMemCount > 0 is rejected",
			annotations: map[string]string{
				shimannotations.VPMemCount: "4",
			},
			wantErr:   true,
			errSubstr: shimannotations.VPMemCount,
		},

		// ----- locked values use case-insensitive match ------------------
		// strings.ToLower is applied to the user-supplied value before
		// comparison, so non-canonical casing is accepted, but values that
		// don't match after lowercasing are rejected.
		{
			name: "VPCIEnabled=False (capitalized) is accepted",
			annotations: map[string]string{
				shimannotations.VPCIEnabled: "False",
			},
			wantErr: false,
		},
		{
			name: "PreferredRootFSType=INITRD (uppercased) is accepted",
			annotations: map[string]string{
				shimannotations.PreferredRootFSType: "INITRD",
			},
			wantErr: false,
		},
		{
			name: "KernelDirectBoot=True (capitalized) is accepted",
			annotations: map[string]string{
				shimannotations.KernelDirectBoot: "True",
			},
			wantErr: false,
		},
		{
			name: "VPCIEnabled with garbage value is rejected",
			annotations: map[string]string{
				shimannotations.VPCIEnabled: "maybe",
			},
			wantErr:   true,
			errSubstr: shimannotations.VPCIEnabled,
		},
		{
			name: "VPMemCount with non-numeric value is rejected",
			annotations: map[string]string{
				shimannotations.VPMemCount: "lots",
			},
			wantErr:   true,
			errSubstr: shimannotations.VPMemCount,
		},

		// ----- previously "disable to default" annotations are now -------
		// ----- rejected outright (default-deny). To disable a feature, ----
		// ----- omit its annotation. ---------------------------------------
		{
			name: "EnableDeferredCommit set at all is rejected (even =false)",
			annotations: map[string]string{
				shimannotations.EnableDeferredCommit: "false",
			},
			wantErr:   true,
			errSubstr: shimannotations.EnableDeferredCommit,
		},
		{
			name: "EnableDeferredCommit=true is rejected",
			annotations: map[string]string{
				shimannotations.EnableDeferredCommit: "true",
			},
			wantErr:   true,
			errSubstr: shimannotations.EnableDeferredCommit,
		},
		{
			name: "EnableColdDiscardHint set at all is rejected (even =false)",
			annotations: map[string]string{
				shimannotations.EnableColdDiscardHint: "false",
			},
			wantErr:   true,
			errSubstr: shimannotations.EnableColdDiscardHint,
		},
		{
			name: "NumaMaximumProcessorsPerNode set at all is rejected (even =0)",
			annotations: map[string]string{
				shimannotations.NumaMaximumProcessorsPerNode: "0",
			},
			wantErr:   true,
			errSubstr: shimannotations.NumaMaximumProcessorsPerNode,
		},
		{
			name: "NumaMaximumProcessorsPerNode > 0 rejected",
			annotations: map[string]string{
				shimannotations.NumaMaximumProcessorsPerNode: "8",
			},
			wantErr:   true,
			errSubstr: shimannotations.NumaMaximumProcessorsPerNode,
		},
		{
			name: "NumaMaximumMemorySizePerNode set at all is rejected",
			annotations: map[string]string{
				shimannotations.NumaMaximumMemorySizePerNode: "0",
			},
			wantErr:   true,
			errSubstr: shimannotations.NumaMaximumMemorySizePerNode,
		},
		{
			name: "NumaCountOfProcessors set at all is rejected (even empty)",
			annotations: map[string]string{
				shimannotations.NumaCountOfProcessors: "",
			},
			wantErr:   true,
			errSubstr: shimannotations.NumaCountOfProcessors,
		},
		{
			name: "non-empty NUMA list rejected",
			annotations: map[string]string{
				shimannotations.NumaCountOfProcessors: "2,2",
			},
			wantErr:   true,
			errSubstr: shimannotations.NumaCountOfProcessors,
		},
		{
			name: "NumaPreferredPhysicalNodes rejected",
			annotations: map[string]string{
				shimannotations.NumaPreferredPhysicalNodes: "0,1",
			},
			wantErr:   true,
			errSubstr: shimannotations.NumaPreferredPhysicalNodes,
		},

		// ----- explicitly disallowed VM annotations -----------------------
		{
			name: "VirtualMachineKernelDrivers rejected",
			annotations: map[string]string{
				shimannotations.VirtualMachineKernelDrivers: `C:\drivers`,
			},
			wantErr:   true,
			errSubstr: shimannotations.VirtualMachineKernelDrivers,
		},
		{
			name: "VPMemNoMultiMapping rejected",
			annotations: map[string]string{
				shimannotations.VPMemNoMultiMapping: "true",
			},
			wantErr:   true,
			errSubstr: shimannotations.VPMemNoMultiMapping,
		},
		{
			name: "UVMConsolePipe rejected",
			annotations: map[string]string{
				iannotations.UVMConsolePipe: `\\.\pipe\foo`,
			},
			wantErr:   true,
			errSubstr: iannotations.UVMConsolePipe,
		},
		{
			name: "CPUGroupID rejected",
			annotations: map[string]string{
				shimannotations.CPUGroupID: "00000000-0000-0000-0000-000000000000",
			},
			wantErr:   true,
			errSubstr: shimannotations.CPUGroupID,
		},
		{
			name: "ResourcePartitionID rejected",
			annotations: map[string]string{
				shimannotations.ResourcePartitionID: "00000000-0000-0000-0000-000000000000",
			},
			wantErr:   true,
			errSubstr: shimannotations.ResourcePartitionID,
		},
		{
			name: "FullyPhysicallyBacked default-denied",
			annotations: map[string]string{
				shimannotations.FullyPhysicallyBacked: "true",
			},
			wantErr:   true,
			errSubstr: shimannotations.FullyPhysicallyBacked,
		},

		// ----- confidential annotations all rejected ----------------------
		{
			name: "LCOWSecurityPolicy rejected",
			annotations: map[string]string{
				shimannotations.LCOWSecurityPolicy: "policy-blob",
			},
			wantErr:   true,
			errSubstr: shimannotations.LCOWSecurityPolicy,
		},
		{
			name: "LCOWSecurityPolicyEnforcer rejected",
			annotations: map[string]string{
				shimannotations.LCOWSecurityPolicyEnforcer: "rego",
			},
			wantErr:   true,
			errSubstr: shimannotations.LCOWSecurityPolicyEnforcer,
		},
		{
			name: "LCOWGuestStateFile rejected",
			annotations: map[string]string{
				shimannotations.LCOWGuestStateFile: `C:\path\to.vmgs`,
			},
			wantErr:   true,
			errSubstr: shimannotations.LCOWGuestStateFile,
		},
		{
			name: "LCOWHclEnabled rejected",
			annotations: map[string]string{
				shimannotations.LCOWHclEnabled: "true",
			},
			wantErr:   true,
			errSubstr: shimannotations.LCOWHclEnabled,
		},
		{
			name: "LCOWReferenceInfoFile rejected",
			annotations: map[string]string{
				shimannotations.LCOWReferenceInfoFile: `C:\info.bin`,
			},
			wantErr:   true,
			errSubstr: shimannotations.LCOWReferenceInfoFile,
		},
		{
			name: "NoSecurityHardware rejected",
			annotations: map[string]string{
				shimannotations.NoSecurityHardware: "true",
			},
			wantErr:   true,
			errSubstr: shimannotations.NoSecurityHardware,
		},
		{
			name: "DmVerityMode rejected",
			annotations: map[string]string{
				shimannotations.DmVerityMode: "true",
			},
			wantErr:   true,
			errSubstr: shimannotations.DmVerityMode,
		},
		{
			name: "DmVerityCreateArgs rejected",
			annotations: map[string]string{
				shimannotations.DmVerityCreateArgs: "args",
			},
			wantErr:   true,
			errSubstr: shimannotations.DmVerityCreateArgs,
		},
		{
			name: "DmVerityRootFsVhd rejected",
			annotations: map[string]string{
				shimannotations.DmVerityRootFsVhd: `C:\rootfs.vhd`,
			},
			wantErr:   true,
			errSubstr: shimannotations.DmVerityRootFsVhd,
		},
		{
			name: "ExtraVSockPorts rejected",
			annotations: map[string]string{
				iannotations.ExtraVSockPorts: "5000,5001",
			},
			wantErr:   true,
			errSubstr: iannotations.ExtraVSockPorts,
		},

		// ----- HvSocket service-table prefix ------------------------------
		{
			name: "UVMHyperVSocketConfigPrefix entry rejected",
			annotations: map[string]string{
				iannotations.UVMHyperVSocketConfigPrefix + "00000000-0000-0000-0000-000000000000": `{"BindSecurityDescriptor":"D:P"}`,
			},
			wantErr:   true,
			errSubstr: iannotations.UVMHyperVSocketConfigPrefix,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateLiveMigrationAnnotations(tc.annotations)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tc.errSubstr != "" && !strings.Contains(err.Error(), tc.errSubstr) {
					t.Fatalf("error %q does not mention offending annotation %q", err, tc.errSubstr)
				}
				if !strings.Contains(err.Error(), shimannotations.LiveMigrationAllowed) {
					t.Fatalf("error %q does not reference %s", err, shimannotations.LiveMigrationAllowed)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestApplyLiveMigrationLockedDefaults(t *testing.T) {
	t.Run("nil map is replaced and populated with all locked defaults", func(t *testing.T) {
		got := applyLiveMigrationLockedDefaults(nil)
		if got == nil {
			t.Fatalf("expected non-nil map, got nil")
		}
		if len(got) != len(liveMigrationLockedVMAnnotations) {
			t.Fatalf("expected %d entries, got %d (%v)",
				len(liveMigrationLockedVMAnnotations), len(got), got)
		}
		for key, want := range liveMigrationLockedVMAnnotations {
			if got[key] != want {
				t.Errorf("key %q: want %q, got %q", key, want, got[key])
			}
		}
	})

	t.Run("empty map is populated with all locked defaults", func(t *testing.T) {
		in := map[string]string{}
		got := applyLiveMigrationLockedDefaults(in)
		for key, want := range liveMigrationLockedVMAnnotations {
			if got[key] != want {
				t.Errorf("key %q: want %q, got %q", key, want, got[key])
			}
		}
	})

	t.Run("missing locked annotations are filled in", func(t *testing.T) {
		in := map[string]string{
			// Only set one of the locked annotations; the rest must be defaulted.
			shimannotations.PreferredRootFSType: "initrd",
			// Plus an unrelated annotation that must be preserved untouched.
			"io.kubernetes.cri.sandbox-id": "abc123",
		}
		got := applyLiveMigrationLockedDefaults(in)
		for key, want := range liveMigrationLockedVMAnnotations {
			if got[key] != want {
				t.Errorf("key %q: want %q, got %q", key, want, got[key])
			}
		}
		if got["io.kubernetes.cri.sandbox-id"] != "abc123" {
			t.Errorf("unrelated annotation was modified: got %q", got["io.kubernetes.cri.sandbox-id"])
		}
	})

	t.Run("user-supplied locked values are not overwritten", func(t *testing.T) {
		// Validation is case-insensitive and accepts non-canonical casing,
		// so a user could legitimately supply e.g. "True" or "INITRD". The
		// defaulter must not clobber such values.
		in := map[string]string{
			shimannotations.KernelDirectBoot:    "True",
			shimannotations.PreferredRootFSType: "INITRD",
		}
		got := applyLiveMigrationLockedDefaults(in)
		if got[shimannotations.KernelDirectBoot] != "True" {
			t.Errorf("KernelDirectBoot: want %q (preserved), got %q",
				"True", got[shimannotations.KernelDirectBoot])
		}
		if got[shimannotations.PreferredRootFSType] != "INITRD" {
			t.Errorf("PreferredRootFSType: want %q (preserved), got %q",
				"INITRD", got[shimannotations.PreferredRootFSType])
		}
	})

	t.Run("output passes validation", func(t *testing.T) {
		// The defaulter's output must round-trip through validation: starting
		// from an empty map, applying defaults, then validating must succeed.
		got := applyLiveMigrationLockedDefaults(nil)
		if err := validateLiveMigrationAnnotations(got); err != nil {
			t.Fatalf("defaulted map failed validation: %v", err)
		}
	})
}
