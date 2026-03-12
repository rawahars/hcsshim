//go:build windows && wcow

package container

import (
	"github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/stats"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/vm/vmutils"
)

func parseContainerStats(props *hcsschema.Properties) *stats.Statistics_Windows {
	return vmutils.ConvertHcsPropertiesToWindowsStats(props)
}
