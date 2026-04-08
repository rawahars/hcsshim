//go:build windows && lcow

package pod

import (
	"context"

	"github.com/Microsoft/hcsshim/internal/controller/device/plan9"
	"github.com/Microsoft/hcsshim/internal/controller/device/scsi"
	"github.com/Microsoft/hcsshim/internal/controller/device/vpci"
	"github.com/Microsoft/hcsshim/internal/controller/network"
	"github.com/Microsoft/hcsshim/internal/vm/guestmanager"
)

type vmController interface {
	RuntimeID() string
	Guest() *guestmanager.Guest
	SCSIController() *scsi.Controller
	VPCIController() *vpci.Controller
	Plan9Controller() *plan9.Controller
	NetworkController() *network.Controller
}

type networkController interface {
	Setup(ctx context.Context, opts *network.SetupOptions) error
	Teardown(ctx context.Context) error
}

// todo: create status and it changes based on the tree below.
// todo: Consider case where sandbox container is not present but someone tries to use
// GetContainer with containerID as podID.
