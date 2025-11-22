package sandbox_options

import (
	"context"
	"fmt"
	"maps"
	"strings"

	"github.com/Microsoft/go-winio/pkg/guid"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/oci"
	"github.com/Microsoft/hcsshim/internal/uvm"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

// BuildUVMOptions creates either LCOW or WCOW options from SandboxSpec.
// Defaults are set by NewDefaultOptionsLCOW/NewDefaultOptionsWCOW and
// then overridden by any fields present in the proto.
func BuildUVMOptions(ctx context.Context, spec *SandboxSpec, id, owner string) (*uvm.OptionsLCOW, *uvm.OptionsWCOW, error) {
	if spec == nil {
		return nil, nil, fmt.Errorf("nil SandboxSpec")
	}

	switch isolation := spec.IsolationLevel.(type) {
	case *SandboxSpec_Process:
		// Process isolation: no UVM to create.
		return nil, nil, fmt.Errorf("uvm options cannot be created for process isolation")

	case *SandboxSpec_Hypervisor:
		hypervisor := isolation.Hypervisor
		if hypervisor == nil {
			return nil, nil, fmt.Errorf("hypervisor section is nil for isolation_level=hypervisor")
		}

		switch platform := hypervisor.Platform.(type) {
		case *HypervisorIsolated_Lcow:
			if platform.Lcow == nil {
				return nil, nil, fmt.Errorf("lcow params are nil for isolation_level=hypervisor")
			}

			optionsLCOW := uvm.NewDefaultOptionsLCOW(id, owner)

			// Platform-specific overlays
			if lb := platform.Lcow.GetLinuxBootOptions(); lb != nil {
				applyLinuxBootOptions(ctx, optionsLCOW, lb)
			}
			if lg := platform.Lcow.GetLinuxGuestOptions(); lg != nil {
				applyLinuxGuestOptions(optionsLCOW, lg)
			}
			if ld := platform.Lcow.GetLinuxDeviceOptions(); ld != nil {
				if err := applyLinuxDeviceOptions(ctx, optionsLCOW, ld); err != nil {
					return nil, nil, err
				}
			}
			if lc := platform.Lcow.GetConfidentialOptions(); lc != nil {
				applyLCOWConfidentialOptions(optionsLCOW, lc)
			}

			// Common overlays
			if cpu := hypervisor.GetCpuConfig(); cpu != nil {
				applyCPUConfig(optionsLCOW.Options, cpu)
			}
			if mem := hypervisor.GetMemoryConfig(); mem != nil {
				applyMemoryConfig(optionsLCOW.Options, mem)
			}
			if sto := hypervisor.GetStorageConfig(); sto != nil {
				applyStorageConfig(optionsLCOW.Options, sto)
			}
			if numa := hypervisor.GetNumaConfig(); numa != nil {
				applyNUMAConfig(optionsLCOW.Options, numa)
			}

			if add := hypervisor.GetAdditionalConfig(); add != nil {
				applyAdditionalConfig(ctx, optionsLCOW.Options, add)
			}

			err := applyHypervisorConfig(optionsLCOW.Options, hypervisor)
			if err != nil {
				return nil, nil, err
			}

			// Some final checks prior to commiting.
			if hypervisor.MemoryConfig.FullyPhysicallyBacked != nil && *hypervisor.MemoryConfig.FullyPhysicallyBacked {
				optionsLCOW.AllowOvercommit = false
				optionsLCOW.VPMemDeviceCount = 0
			}

			return optionsLCOW, nil, nil

		case *HypervisorIsolated_Wcow:
			if platform.Wcow == nil {
				return nil, nil, fmt.Errorf("wcow params are nil for isolation_level=hypervisor")
			}

			optionsWCOW := uvm.NewDefaultOptionsWCOW(id, owner)

			// Platform-specific overlays
			if wb := platform.Wcow.GetWindowsBootOptions(); wb != nil {
				applyWindowsBootOptions(optionsWCOW, wb)
			}
			if wg := platform.Wcow.GetWindowsGuestOptions(); wg != nil {
				if err := applyWindowsGuestOptions(ctx, optionsWCOW, wg); err != nil {
					return nil, nil, err
				}
			}
			if wc := platform.Wcow.GetConfidentialOptions(); wc != nil {
				err := applyWCOWConfidentialOptions(optionsWCOW, wc)
				if err != nil {
					return nil, nil, err
				}
			}

			// Common overlays
			if cpu := hypervisor.GetCpuConfig(); cpu != nil {
				applyCPUConfig(optionsWCOW.Options, cpu)
			}
			if mem := hypervisor.GetMemoryConfig(); mem != nil {
				applyMemoryConfig(optionsWCOW.Options, mem)
			}
			if sto := hypervisor.GetStorageConfig(); sto != nil {
				applyStorageConfig(optionsWCOW.Options, sto)
			}
			if numa := hypervisor.GetNumaConfig(); numa != nil {
				applyNUMAConfig(optionsWCOW.Options, numa)
			}
			if add := hypervisor.GetAdditionalConfig(); add != nil {
				applyAdditionalConfig(ctx, optionsWCOW.Options, add)
			}

			err := applyHypervisorConfig(optionsWCOW.Options, hypervisor)
			if err != nil {
				return nil, nil, err
			}

			// Some final checks prior to commiting.
			if hypervisor.MemoryConfig.FullyPhysicallyBacked != nil && *hypervisor.MemoryConfig.FullyPhysicallyBacked {
				optionsWCOW.AllowOvercommit = false
			}

			return nil, optionsWCOW, nil

		default:
			return nil, nil, fmt.Errorf("hypervisor.platform must be LCOW or WCOW")
		}

	default:
		return nil, nil, fmt.Errorf("unknown isolation_level")
	}
}

// -----------------------------------------------------------------------------
// Common overlays
// -----------------------------------------------------------------------------

func applyCPUConfig(common *uvm.Options, cpu *CPUConfig) {
	// processor_count: unset => keep defaults; set==0 => error
	if cpu.ProcessorCount != nil && *cpu.ProcessorCount > 0 {
		common.ProcessorCount = *cpu.ProcessorCount
	}

	// processor_limit: unset => keep defaults; set==0 => error
	if cpu.ProcessorLimit != nil && *cpu.ProcessorLimit > 0 {
		common.ProcessorLimit = *cpu.ProcessorLimit
	}

	// processor_weight: unset => keep defaults; set==0 => error
	if cpu.ProcessorWeight != nil && *cpu.ProcessorWeight > 0 {
		common.ProcessorWeight = *cpu.ProcessorWeight
	}
}

func applyMemoryConfig(common *uvm.Options, mem *MemoryConfig) {
	// Additional check to ensure that Memory Size is non-zero.
	if mem.MemorySizeInMb != nil && *mem.MemorySizeInMb > 0 {
		common.MemorySizeInMB = *mem.MemorySizeInMb
	}

	// MMIO: only overlay when non-zero in proto (your defaults are zero unless tuned)
	setU64(&common.LowMMIOGapInMB, mem.LowMmioGapInMb)
	setU64(&common.HighMMIOBaseInMB, mem.HighMmioBaseInMb)
	setU64(&common.HighMMIOGapInMB, mem.HighMmioGapInMb)

	setBool(&common.AllowOvercommit, mem.AllowOvercommit)
	setBool(&common.FullyPhysicallyBacked, mem.FullyPhysicallyBacked)
	setBool(&common.EnableDeferredCommit, mem.EnableDeferredCommit)
}

func applyStorageConfig(common *uvm.Options, sto *StorageConfig) {
	if sto.StorageQosIopsMaximum != nil && *sto.StorageQosIopsMaximum > 0 {
		common.StorageQoSIopsMaximum = *sto.StorageQosIopsMaximum
	}

	if sto.StorageQosBandwidthMaximum != nil && *sto.StorageQosBandwidthMaximum > 0 {
		common.StorageQoSBandwidthMaximum = *sto.StorageQosBandwidthMaximum
	}

	setBool(&common.NoWritableFileShares, sto.NoWritableFileShares)
}

func applyNUMAConfig(common *uvm.Options, n *NUMAConfig) {
	setU32(&common.MaxProcessorsPerNumaNode, n.MaxProcessorsPerNumaNode)
	setU64(&common.MaxMemorySizePerNumaNode, n.MaxMemorySizePerNumaNode)

	if len(n.PreferredPhysicalNumaNodes) > 0 {
		common.PreferredPhysicalNumaNodes = copyU32(n.PreferredPhysicalNumaNodes)
	}
	if len(n.NumaMappedPhysicalNodes) > 0 {
		common.NumaMappedPhysicalNodes = copyU32(n.NumaMappedPhysicalNodes)
	}
	if len(n.NumaProcessorCounts) > 0 {
		common.NumaProcessorCounts = copyU32(n.NumaProcessorCounts)
	}
	if len(n.NumaMemoryBlocksCounts) > 0 {
		common.NumaMemoryBlocksCounts = copyU64(n.NumaMemoryBlocksCounts)
	}
}

func applyAdditionalConfig(ctx context.Context, common *uvm.Options, a *AdditionalConfig) {
	setStr(&common.NetworkConfigProxy, a.NetworkConfigProxy)
	setStr(&common.ProcessDumpLocation, a.ProcessDumpLocation)
	setStr(&common.DumpDirectoryPath, a.DumpDirectoryPath)
	setStr(&common.ConsolePipe, a.ConsolePipe)

	if len(a.AdditionalHypervConfig) > 0 {
		maps.Copy(common.AdditionalHyperVConfig, parseHVSocketServiceTable(ctx, a.AdditionalHypervConfig))
	}
}

func parseHVSocketServiceTable(ctx context.Context, hyperVConfig map[string]*HvSocketServiceConfig) map[string]hcsschema.HvSocketServiceConfig {
	parsedServiceTable := make(map[string]hcsschema.HvSocketServiceConfig)

	for key, val := range hyperVConfig {
		parsedGuid, err := guid.FromString(key)
		if err != nil {
			log.G(ctx).WithError(err).Warn("invalid GUID string for Hyper-V socket service configuration annotation")
			continue
		}
		guidStr := parsedGuid.String() // overwrite the GUID string to standardize format (capitalization)

		cfg := hcsschema.HvSocketServiceConfig{}
		setStr(&cfg.BindSecurityDescriptor, val.BindSecurityDescriptor)
		setStr(&cfg.ConnectSecurityDescriptor, val.ConnectSecurityDescriptor)
		setBool(&cfg.AllowWildcardBinds, val.AllowWildcardBinds)
		setBool(&cfg.Disabled, val.Disabled)

		if _, found := parsedServiceTable[guidStr]; found {
			log.G(ctx).WithFields(logrus.Fields{
				"guid": guidStr,
			}).Warn("overwritting existing Hyper-V socket service configuration")
		}

		if log.G(ctx).Logger.IsLevelEnabled(logrus.TraceLevel) {
			log.G(ctx).WithField("configuration", log.Format(ctx, cfg)).Trace("found Hyper-V socket service configuration annotation")
		}

		parsedServiceTable[guidStr] = cfg
	}

	return parsedServiceTable
}

func applyHypervisorConfig(common *uvm.Options, hypervisor *HypervisorIsolated) error {
	setStr(&common.CPUGroupID, hypervisor.CpuGroupId)

	if hypervisor.ResourcePartitionId != nil {
		resourcePartitionId := *hypervisor.ResourcePartitionId
		resourcePartitionIdGuid, err := guid.FromString(resourcePartitionId)
		if err != nil {
			return fmt.Errorf("failed to parse resource partition id %q to GUID: %w", resourcePartitionId, err)
		}
		common.ResourcePartitionID = &resourcePartitionIdGuid
	}

	return nil
}

// -----------------------------------------------------------------------------
// LCOW overlays
// -----------------------------------------------------------------------------

func applyLinuxBootOptions(ctx context.Context, opts *uvm.OptionsLCOW, lb *LinuxBootOptions) {
	setBool(&opts.EnableColdDiscardHint, lb.EnableColdDiscardHint)

	if lb.BootFilesPath != nil {
		// Prefer the helper to update associated fields automatically.
		opts.UpdateBootFilesPath(ctx, *lb.BootFilesPath)
	}

	setStr(&opts.KernelBootOptions, lb.KernelBootOptions)

	setBool(&opts.KernelDirect, lb.KernelDirect)
	if !opts.KernelDirect {
		opts.KernelFile = uvm.KernelFile
	}

	if lb.PreferredRootFsType != nil {
		if *lb.PreferredRootFsType == PreferredRootFSType_PREFERRED_ROOT_FS_TYPE_INITRD {
			opts.PreferredRootFSType = uvm.PreferredRootFSTypeInitRd
		} else if *lb.PreferredRootFsType == PreferredRootFSType_PREFERRED_ROOT_FS_TYPE_VHD {
			opts.PreferredRootFSType = uvm.PreferredRootFSTypeVHD
		} else {
			log.G(ctx).Warn("PreferredRootFsType must be 'initrd' or 'vhd'")
		}
	}

	switch opts.PreferredRootFSType {
	case uvm.PreferredRootFSTypeInitRd:
		opts.RootFSFile = uvm.InitrdFile
	case uvm.PreferredRootFSTypeVHD:
		opts.RootFSFile = uvm.VhdFile
	}

	// HCL is presence-aware
	if lb.HclEnabled != nil {
		val := *lb.HclEnabled
		opts.HclEnabled = &val
	} else {
		opts.HclEnabled = nil
	}
}

func applyLinuxGuestOptions(opts *uvm.OptionsLCOW, lg *LinuxGuestOptions) {
	setBool(&opts.DisableTimeSyncService, lg.DisableTimeSyncService)

	if len(lg.ExtraVsockPorts) > 0 {
		opts.ExtraVSockPorts = copyU32(lg.ExtraVsockPorts)
	}
	setBool(&opts.PolicyBasedRouting, lg.PolicyBasedRouting)
	setBool(&opts.WritableOverlayDirs, lg.WritableOverlayDirs)
}

func applyLinuxDeviceOptions(ctx context.Context, opts *uvm.OptionsLCOW, ld *LinuxDeviceOptions) error {
	setU32(&opts.VPMemDeviceCount, ld.VpMemDeviceCount)
	setU64(&opts.VPMemSizeBytes, ld.VpMemSizeBytes)
	setBool(&opts.VPMemNoMultiMapping, ld.VpMemNoMultiMapping)
	setBool(&opts.VPCIEnabled, ld.VpciEnabled)

	windowsDevices := make([]specs.WindowsDevice, 0, len(ld.AssignedDevices))
	for idx, device := range ld.AssignedDevices {
		windowsDevices[idx] = specs.WindowsDevice{
			ID:     device.Id,
			IDType: device.IdType,
		}
	}
	opts.AssignedDevices = oci.ParseDevices(ctx, windowsDevices)

	return nil
}

func applyLCOWConfidentialOptions(opts *uvm.OptionsLCOW, lc *LCOWConfidentialOptions) {
	if lc.Options != nil {
		applyCommonConfidentialLCOW(opts.ConfidentialOptions, lc.Options)
	}
	setStr(&opts.ConfidentialOptions.DmVerityRootFsVhd, lc.DmVerityRootFsVhd)
	setBool(&opts.ConfidentialOptions.DmVerityMode, lc.DmVerityMode)
	setStr(&opts.ConfidentialOptions.DmVerityCreateArgs, lc.DmVerityCreateArgs)

	if lc.Options.NoSecurityHardware != nil {
		oci.HandleLCOWSecurityPolicyWithNoSecurityHardware(*lc.Options.NoSecurityHardware, opts)
	}

	if len(opts.SecurityPolicy) > 0 {
		opts.EnableScratchEncryption = true
	}

	if lc.EnableScratchEncryption != nil {
		setBool(&opts.EnableScratchEncryption, lc.EnableScratchEncryption)
	}
}

// -----------------------------------------------------------------------------
// WCOW overlays
// -----------------------------------------------------------------------------

func applyWindowsBootOptions(opts *uvm.OptionsWCOW, wb *WindowsBootOptions) {
	setBool(&opts.Options.DisableCompartmentNamespace, wb.DisableCompartmentNamespace)
	setBool(&opts.NoDirectMap, wb.NoDirectMap)
}

func applyWindowsGuestOptions(ctx context.Context, opts *uvm.OptionsWCOW, wg *WindowsGuestOptions) error {
	setBool(&opts.NoInheritHostTimezone, wg.NoInheritHostTimezone)

	if len(wg.AdditionalRegistryKeys) != 0 {
		opts.AdditionalRegistryKeys = append(opts.AdditionalRegistryKeys,
			oci.ValidateAndFilterRegistryValues(ctx, registryValuesFromProto(wg))...)
	}
	return nil
}

func applyWCOWConfidentialOptions(opts *uvm.OptionsWCOW, wc *WCOWConfidentialOptions) error {
	if wc.Options != nil {
		applyCommonConfidentialWCOW(opts.ConfidentialWCOWOptions, wc.Options)
	}

	if len(opts.SecurityPolicy) > 0 {
		opts.SecurityPolicyEnabled = true
		setBool(&opts.ConfidentialWCOWOptions.DisableSecureBoot, wc.DisableSecureBoot)

		opts.IsolationType = "SecureNestedPaging"
		if wc.Options.NoSecurityHardware != nil && *wc.Options.NoSecurityHardware {
			opts.IsolationType = "GuestStateOnly"
		}
		setStr(&opts.IsolationType, wc.IsolationType)
		err := oci.HandleWCOWIsolationType(opts.IsolationType, opts)
		if err != nil {
			return err
		}
	}
	setStr(&opts.ConfidentialWCOWOptions.IsolationType, wc.IsolationType)

	setBool(&opts.ConfidentialWCOWOptions.WritableEFI, wc.WritableEfi)

	return nil
}

// -----------------------------------------------------------------------------
// Confidential (common)
// -----------------------------------------------------------------------------

func applyCommonConfidentialLCOW(opts *uvm.ConfidentialOptions, c *ConfidentialOptions) {
	setStr(&opts.GuestStateFile, c.GuestStateFile)
	setStr(&opts.SecurityPolicy, c.SecurityPolicy)
	setStr(&opts.SecurityPolicyEnforcer, c.SecurityPolicyEnforcer)
	setStr(&opts.UVMReferenceInfoFile, c.UvmReferenceInfoFile)
}

func applyCommonConfidentialWCOW(opts *uvm.ConfidentialWCOWOptions, c *ConfidentialOptions) {
	setStr(&opts.GuestStateFilePath, c.GuestStateFile)
	setStr(&opts.SecurityPolicy, c.SecurityPolicy)
	setStr(&opts.SecurityPolicyEnforcer, c.SecurityPolicyEnforcer)
	setStr(&opts.UVMReferenceInfoFile, c.UvmReferenceInfoFile)
}

// -----------------------------------------------------------------------------
// Small utilities to reduce nil-check boilerplate
// -----------------------------------------------------------------------------

func setStr(dst *string, src *string) {
	if src != nil {
		*dst = *src
	}
}

func setBool(dst *bool, src *bool) {
	if src != nil {
		*dst = *src
	}
}

func setU32(dst *uint32, src *uint32) {
	if src != nil {
		*dst = *src
	}
}

func setU64(dst *uint64, src *uint64) {
	if src != nil {
		*dst = *src
	}
}

func copyU32(in []uint32) []uint32 {
	out := make([]uint32, len(in))
	copy(out, in)
	return out
}

func copyU64(in []uint64) []uint64 {
	out := make([]uint64, len(in))
	copy(out, in)
	return out
}

// Proto adapter: map proto values to hcsschema.RegistryValue.
func registryValuesFromProto(wgo *WindowsGuestOptions) []hcsschema.RegistryValue {
	if wgo == nil || len(wgo.AdditionalRegistryKeys) == 0 {
		return []hcsschema.RegistryValue{}
	}

	out := make([]hcsschema.RegistryValue, 0, len(wgo.AdditionalRegistryKeys))
	for _, pv := range wgo.AdditionalRegistryKeys {
		if pv == nil {
			continue
		}

		var key *hcsschema.RegistryKey
		if pv.Key != nil {
			key = &hcsschema.RegistryKey{
				Hive:     mapProtoHive(pv.Key.Hive),
				Name:     strings.TrimSpace(pv.Key.Name),
				Volatile: pv.Key.Volatile,
			}
		}

		out = append(out, hcsschema.RegistryValue{
			Key:         key,
			Name:        strings.TrimSpace(pv.Name),
			Type_:       mapProtoRegValueType(pv.Type),
			StringValue: pv.StringValue,
			BinaryValue: pv.BinaryValue,
			DWordValue:  pv.DwordValue,
			QWordValue:  pv.QwordValue,
			CustomType:  pv.CustomType,
		})
	}
	return out
}

func mapProtoHive(h RegistryHive) hcsschema.RegistryHive {
	switch h {
	case RegistryHive_REGISTRY_HIVE_SYSTEM:
		return hcsschema.RegistryHive_SYSTEM
	case RegistryHive_REGISTRY_HIVE_SOFTWARE:
		return hcsschema.RegistryHive_SOFTWARE
	case RegistryHive_REGISTRY_HIVE_SECURITY:
		return hcsschema.RegistryHive_SECURITY
	case RegistryHive_REGISTRY_HIVE_SAM:
		return hcsschema.RegistryHive_SAM
	default:
		return hcsschema.RegistryHive_SYSTEM
	}
}

func mapProtoRegValueType(t RegistryValueType) hcsschema.RegistryValueType {
	switch t {
	case RegistryValueType_REGISTRY_VALUE_TYPE_NONE:
		return hcsschema.RegistryValueType_NONE
	case RegistryValueType_REGISTRY_VALUE_TYPE_STRING:
		return hcsschema.RegistryValueType_STRING
	case RegistryValueType_REGISTRY_VALUE_TYPE_EXPANDED_STRING:
		return hcsschema.RegistryValueType_EXPANDED_STRING
	case RegistryValueType_REGISTRY_VALUE_TYPE_MULTI_STRING:
		return hcsschema.RegistryValueType_MULTI_STRING
	case RegistryValueType_REGISTRY_VALUE_TYPE_BINARY:
		return hcsschema.RegistryValueType_BINARY
	case RegistryValueType_REGISTRY_VALUE_TYPE_D_WORD:
		return hcsschema.RegistryValueType_D_WORD
	case RegistryValueType_REGISTRY_VALUE_TYPE_Q_WORD:
		return hcsschema.RegistryValueType_Q_WORD
	case RegistryValueType_REGISTRY_VALUE_TYPE_CUSTOM_TYPE:
		return hcsschema.RegistryValueType_CUSTOM_TYPE
	default:
		return hcsschema.RegistryValueType_NONE
	}
}
