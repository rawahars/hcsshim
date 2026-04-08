//go:build windows && lcow

package linuxcontainer

import (
	"context"

	plan9Mount "github.com/Microsoft/hcsshim/internal/controller/device/plan9/mount"
	"github.com/Microsoft/hcsshim/internal/controller/device/plan9/share"
	"github.com/Microsoft/hcsshim/internal/controller/device/scsi/disk"
	scsiMount "github.com/Microsoft/hcsshim/internal/controller/device/scsi/mount"
	"github.com/Microsoft/hcsshim/internal/controller/device/vpci"
	"github.com/Microsoft/hcsshim/internal/gcs"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/opencontainers/runtime-spec/specs-go"
)

// CreateContainerOpts holds additional options for container creation.
type CreateContainerOpts struct {
	IsScratchEncryptionEnabled bool
}

// vmHostedContainerSettingsV2 defines the portion of the
// ContainerCreate.ContainerConfig that is sent via a V2 call for LCOW.
type vmHostedContainerSettingsV2 struct {
	SchemaVersion    *hcsschema.Version
	OCIBundlePath    string      `json:"OciBundlePath,omitempty"`
	OCISpecification *specs.Spec `json:"OciSpecification,omitempty"`
	// ScratchDirPath represents the path inside the UVM at which the container scratch
	// directory is present.  Usually, this is the path at which the container scratch
	// VHD is mounted inside the UVM. But in case of scratch sharing this is a
	// directory under the UVM scratch directory.
	ScratchDirPath string
}

type guest interface {
	Capabilities() gcs.GuestDefinedCapabilities
	CreateContainer(ctx context.Context, cid string, config interface{}) (*gcs.Container, error)
	DeleteContainerState(ctx context.Context, cid string) error

	AddLCOWCombinedLayers(ctx context.Context, settings guestresource.LCOWCombinedLayers) error
	RemoveLCOWCombinedLayers(ctx context.Context, settings guestresource.LCOWCombinedLayers) error
}

type scsiController interface {
	Reserve(ctx context.Context, diskConfig disk.Config, mountConfig scsiMount.Config) (guid.GUID, error)
	UnmapFromGuest(ctx context.Context, reservation guid.GUID) error
	MapToGuest(ctx context.Context, id guid.GUID) (string, error)
}

type plan9Controller interface {
	Reserve(ctx context.Context, shareConfig share.Config, mountConfig plan9Mount.Config) (guid.GUID, error)
	UnmapFromGuest(ctx context.Context, reservation guid.GUID) error
	MapToGuest(ctx context.Context, id guid.GUID) (string, error)
}

type vPCIController interface {
	Reserve(ctx context.Context, device vpci.Device) (guid.GUID, error)
	RemoveFromVM(ctx context.Context, vmBusGUID guid.GUID) error
	AddToVM(ctx context.Context, vmBusGUID guid.GUID) error
}
