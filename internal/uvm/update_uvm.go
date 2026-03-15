//go:build windows

package uvm

import (
	"context"
)

// Update modifies the resources of the utility VM.
// For WCOW, data should be *specs.WindowsResources.
// For LCOW, data should be *specs.LinuxResources or *ctrdtaskapi.PolicyFragment.
func (uvm *UtilityVM) Update(ctx context.Context, data interface{}, annots map[string]string) error {
	if uvm.operatingSystem == "windows" {
		return uvm.updateWCOW(ctx, data, annots)
	}
	return uvm.updateLCOW(ctx, data, annots)
}
