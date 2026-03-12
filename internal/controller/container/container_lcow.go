//go:build windows && !wcow

package container

import (
	"github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/stats"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
)

func parseContainerStats(props *hcsschema.Properties) *stats.Statistics_Linux {
	return &stats.Statistics_Linux{Linux: props.Metrics}
}
