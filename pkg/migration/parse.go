//go:build windows

package migration

import (
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
)

// InitializeOptionsToProto converts [hcsschema.MigrationInitializeOptions]
// to its protobuf representation.
func InitializeOptionsToProto(s *hcsschema.MigrationInitializeOptions) *InitializeOptions {
	if s == nil {
		return nil
	}
	return &InitializeOptions{
		MemoryTransport:                  memoryTransportToProto(s.MemoryTransport),
		MemoryTransferThrottleParams:     throttleParamsToProto(s.MemoryTransferThrottleParams),
		CompressionSettings:              compressionSettingsToProto(s.CompressionSettings),
		ChecksumVerification:             s.ChecksumVerification,
		PerfTracingEnabled:               s.PerfTracingEnabled,
		CancelIfBlackoutThresholdExceeds: s.CancelIfBlackoutThresholdExceeds,
		PrepareMemoryTransferMode:        s.PrepareMemoryTransferMode,
		CompatibilityData:                compatibilityInfoToProto(s.CompatibilityData),
	}
}

// InitializeOptionsFromProto converts a protobuf [InitializeOptions] to the
// HCS schema [hcsschema.MigrationInitializeOptions].
func InitializeOptionsFromProto(p *InitializeOptions) *hcsschema.MigrationInitializeOptions {
	if p == nil {
		return nil
	}
	return &hcsschema.MigrationInitializeOptions{
		MemoryTransport:                  memoryTransportFromProto(p.MemoryTransport),
		MemoryTransferThrottleParams:     throttleParamsFromProto(p.MemoryTransferThrottleParams),
		CompressionSettings:              compressionSettingsFromProto(p.CompressionSettings),
		ChecksumVerification:             p.ChecksumVerification,
		PerfTracingEnabled:               p.PerfTracingEnabled,
		CancelIfBlackoutThresholdExceeds: p.CancelIfBlackoutThresholdExceeds,
		PrepareMemoryTransferMode:        p.PrepareMemoryTransferMode,
		CompatibilityData:                compatibilityInfoFromProto(p.CompatibilityData),
	}
}

// memoryTransportToProto converts an HCS [hcsschema.MigrationMemoryTransport] to its protobuf [MemoryTransport] enum value.
func memoryTransportToProto(t hcsschema.MigrationMemoryTransport) MemoryTransport {
	switch t {
	case hcsschema.MigrationMemoryTransportTCP:
		return MemoryTransport_MEMORY_TRANSPORT_TCP
	default:
		return MemoryTransport_MEMORY_TRANSPORT_UNSPECIFIED
	}
}

// memoryTransportFromProto converts a protobuf [MemoryTransport] enum value to its HCS [hcsschema.MigrationMemoryTransport] equivalent.
func memoryTransportFromProto(t MemoryTransport) hcsschema.MigrationMemoryTransport {
	switch t {
	case MemoryTransport_MEMORY_TRANSPORT_TCP:
		return hcsschema.MigrationMemoryTransportTCP
	default:
		return ""
	}
}

// throttleParamsToProto converts an HCS [hcsschema.MemoryMigrationTransferThrottleParams] to its protobuf [MemoryTransferThrottleParams] representation.
func throttleParamsToProto(s *hcsschema.MemoryMigrationTransferThrottleParams) *MemoryTransferThrottleParams {
	if s == nil {
		return nil
	}
	p := &MemoryTransferThrottleParams{
		SkipThrottling:                              s.SkipThrottling,
		ThrottlingScale:                             s.ThrottlingScale,
		TargetNumberOfBrownoutTransferPasses:        s.TargetNumberOfBrownoutTransferPasses,
		StartingBrownoutPassNumberForThrottling:     s.StartingBrownoutPassNumberForThrottling,
		MaximumNumberOfBrownoutTransferPasses:       s.MaximumNumberOfBrownoutTransferPasses,
		TargetBlackoutTransferTime:                  s.TargetBlackoutTransferTime,
		BlackoutTimeThresholdForCancellingMigration: s.BlackoutTimeThresholdForCancellingMigration,
	}
	if s.MinimumThrottlePercentage != nil {
		v := uint32(*s.MinimumThrottlePercentage)
		p.MinimumThrottlePercentage = &v
	}
	return p
}

// throttleParamsFromProto converts a protobuf [MemoryTransferThrottleParams] to its HCS [hcsschema.MemoryMigrationTransferThrottleParams] equivalent.
func throttleParamsFromProto(p *MemoryTransferThrottleParams) *hcsschema.MemoryMigrationTransferThrottleParams {
	if p == nil {
		return nil
	}
	s := &hcsschema.MemoryMigrationTransferThrottleParams{
		SkipThrottling:                              p.SkipThrottling,
		ThrottlingScale:                             p.ThrottlingScale,
		TargetNumberOfBrownoutTransferPasses:        p.TargetNumberOfBrownoutTransferPasses,
		StartingBrownoutPassNumberForThrottling:     p.StartingBrownoutPassNumberForThrottling,
		MaximumNumberOfBrownoutTransferPasses:       p.MaximumNumberOfBrownoutTransferPasses,
		TargetBlackoutTransferTime:                  p.TargetBlackoutTransferTime,
		BlackoutTimeThresholdForCancellingMigration: p.BlackoutTimeThresholdForCancellingMigration,
	}
	if p.MinimumThrottlePercentage != nil {
		v := uint8(*p.MinimumThrottlePercentage)
		s.MinimumThrottlePercentage = &v
	}
	return s
}

// compressionSettingsToProto converts an HCS [hcsschema.MigrationCompressionSettings] to its protobuf [CompressionSettings] representation.
func compressionSettingsToProto(s *hcsschema.MigrationCompressionSettings) *CompressionSettings {
	if s == nil {
		return nil
	}
	return &CompressionSettings{
		ThrottleWorkerCount: s.ThrottleWorkerCount,
	}
}

// compressionSettingsFromProto converts a protobuf [CompressionSettings] to its HCS [hcsschema.MigrationCompressionSettings] equivalent.
func compressionSettingsFromProto(p *CompressionSettings) *hcsschema.MigrationCompressionSettings {
	if p == nil {
		return nil
	}
	return &hcsschema.MigrationCompressionSettings{
		ThrottleWorkerCount: p.ThrottleWorkerCount,
	}
}

// compatibilityInfoToProto converts an HCS [hcsschema.CompatibilityInfo] to its protobuf [CompatibilityInfo] representation.
func compatibilityInfoToProto(s *hcsschema.CompatibilityInfo) *CompatibilityInfo {
	if s == nil {
		return nil
	}
	return &CompatibilityInfo{
		Data: s.Data,
	}
}

// compatibilityInfoFromProto converts a protobuf [CompatibilityInfo] to its HCS [hcsschema.CompatibilityInfo] equivalent.
func compatibilityInfoFromProto(p *CompatibilityInfo) *hcsschema.CompatibilityInfo {
	if p == nil {
		return nil
	}
	return &hcsschema.CompatibilityInfo{
		Data: p.Data,
	}
}
