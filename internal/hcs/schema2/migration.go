package hcsschema

// A set of options for migration workflow
type MigrationInitializeOptions struct {
	// Which side of migration is the workflow performed on
	Origin MigrationOrigin `json:"Origin,omitempty"`
	// Settings for memory transfer during migration. On source, this setting is required when
	// migration is started. On destination, this setting is required when migration is initiated
	MemoryTransport MigrationMemoryTransport `json:"MemoryTransport,omitempty"`
	// Settings for throttling during memory transfer
	MemoryTransferThrottleParams *MemoryMigrationTransferThrottleParams `json:"MemoryTransferThrottleParams,omitempty"`
	// If compression is enabled, additional settings can be configured with this setting
	CompressionSettings *MigrationCompressionSettings `json:"CompressionSettings,omitempty"`
	// Enable memory checksum verification.
	ChecksumVerification bool `json:"ChecksumVerification,omitempty"`
	// Enable performance tracing during migration
	PerfTracingEnabled bool `json:"PerfTracingEnabled,omitempty"`
	// Operation is cancelled if blackout threshold exceeds
	CancelIfBlackoutThresholdExceeds bool `json:"CancelIfBlackoutThresholdExceeds,omitempty"`
	// Specific mode extending timeout for when live migrating cross-version machine
	PrepareMemoryTransferMode bool `json:"PrepareMemoryTransferMode,omitempty"`
	// Compatibility information required for destination VM
	CompatibilityData *CompatibilityInfo `json:"CompatibilityData,omitempty"`
}

// A set of additional options used for HcsLiveMigrationFinalization
type MigrationFinalizedOptions struct {
	// Which side of migration is the workflow performed on
	Origin MigrationOrigin `json:"Origin,omitempty"`
	// The final state transition for the VM as part of concluding LM workflow
	FinalizedOperation MigrationFinalOperation `json:"FinalizedOperation,omitempty"`
}

type MigrationStartOptions struct {
	// Network settings for socket provided
	NetworkSettings *MigrationNetworkSettings `json:"NetworkSettings,omitempty"`
}

type MigrationTransferOptions struct {
	// Which side of migration is the workflow performed on
	Origin MigrationOrigin `json:"Origin,omitempty"`
}

type StartOptions struct {
	// Settings to use when starting a migration on destination side
	DestinationMigrationOptions *MigrationStartOptions `json:"DestinationMigrationOptions,omitempty"`
}

// Where migration is initiated from
type MigrationOrigin string

const (
	MigrationOriginSource      MigrationOrigin = "Source"
	MigrationOriginDestination MigrationOrigin = "Destination"
)

// Transport protocol used for memory transfer during migration
type MigrationMemoryTransport string

const (
	// The memory of the VM being migrated is copied over TCP/IP connection
	MigrationMemoryTransportTCP MigrationMemoryTransport = "TCP"
)

// Settings for migration memory transfer throttling
type MemoryMigrationTransferThrottleParams struct {
	// A flag indicating if throttling should be skipped
	SkipThrottling bool `json:"SkipThrottling,omitempty"`
	// The scale of the throttling. The value is in percentage (1-100).
	ThrottlingScale float64 `json:"ThrottlingScale,omitempty"`
	// Minimum percentage value to which memory transfer can be throttled
	MinimumThrottlePercentage uint8 `json:"MinimumThrottlePercentage,omitempty"`
	// Number of memory transfer passes targetted before the VM enters blackout
	TargetNumberOfBrownoutTransferPasses uint32 `json:"TargetNumberOfBrownoutTransferPasses,omitempty"`
	// The starting transfer pass where throttling is starting
	StartingBrownoutPassNumberForThrottling uint32 `json:"StartingBrownoutPassNumberForThrottling,omitempty"`
	// Maximum number of memory transfer passes before forcing the VM to enter blackout
	MaximumNumberOfBrownoutTransferPasses uint32 `json:"MaximumNumberOfBrownoutTransferPasses,omitempty"`
	// Expected duration for blackout transfer time
	TargetBlackoutTransferTime uint32 `json:"TargetBlackoutTransferTime,omitempty"`
	// Threshold for blackout duration prior to cancelling migration
	BlackoutTimeThresholdForCancellingMigration uint32 `json:"BlackoutTimeThresholdForCancellingMigration,omitempty"`
}

type MigrationCompressionSettings struct {
	// [De]compression thread count. If the value is higher than what the physical host's and VM's configuration can
	// support, the value will be adjusted. The value should be non-zero.
	ThrottleWorkerCount *uint32 `json:"ThrottleWorkerCount,omitempty"`
}

// An opaque VM compatibility data, which is primarily used in migration.
// This should be provided in MigrationInitializeOptions::CompatibilityData
type CompatibilityInfo struct {
	Data []byte `json:"Data,omitempty"`
}

// Final operation performed on the compute system to finalize live migration workflow
type MigrationFinalOperation string

const (
	// Resume the VM
	MigrationFinalOperationResume MigrationFinalOperation = "Resume"
	// Stop the VM
	MigrationFinalOperationStop MigrationFinalOperation = "Stop"
)

// Transport protocol for network connection provided by client
type MigrationNetworkSettings struct {
	// The session ID associated to the socket connection between source and destination
	SessionID uint32 `json:"SessionId,omitempty"`
}
