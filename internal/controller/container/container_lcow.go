//go:build windows && !wcow

package container

import (
	"context"

	"github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/stats"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
)

// teardownContainer attempts a graceful shutdown of the container.
// If shutdown fails or the container does not exit in time,
// it falls back to a forceful terminate.
// This is not applicable for LCOW guests.
func (m *Manager) teardownContainer(_ context.Context) {}

func parseContainerStats(props *hcsschema.Properties) *stats.Statistics_Linux {
	return &stats.Statistics_Linux{Linux: props.Metrics}
}

func (m *Manager) updateContainerResources(ctx context.Context, data interface{}) error {
	resources, ok := data.(*specs.LinuxResources)
	if !ok {
		return errors.New("container resources must be of type *specs.LinuxResources")
	}

	return m.container.Modify(ctx, guestrequest.ModificationRequest{
		ResourceType: guestresource.ResourceTypeContainerConstraints,
		RequestType:  guestrequest.RequestTypeUpdate,
		Settings: guestresource.LCOWContainerConstraints{
			Linux: *resources,
		},
	})
}
