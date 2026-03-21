//go:build windows

package lcow

import (
	"context"
	"fmt"

	runhcsoptions "github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/options"
	"github.com/Microsoft/hcsshim/internal/oci"
	"github.com/opencontainers/runtime-spec/specs-go"
)

func UpdateOCISpec(ctx context.Context, spec *specs.Spec, shimOpts *runhcsoptions.Options) error {
	// apply any updates to the OCI Spec based on the shim options.
	*spec = oci.UpdateSpecFromOptions(*spec, shimOpts)

	// expand annotations after defaults have been loaded in from options
	err := oci.ProcessAnnotations(ctx, spec.Annotations)
	// since annotation expansion is used to toggle security features
	// raise it rather than suppress and move on
	if err != nil {
		return fmt.Errorf("unable to process OCI Spec annotations: %w", err)
	}

	// containerd might not set these params and therefore,
	// the onus of populating the same falls on the shim.
	if spec.Windows == nil {
		spec.Windows = &specs.Windows{}
	}
	if spec.Windows.HyperV == nil {
		spec.Windows.HyperV = &specs.WindowsHyperV{}
	}

	// Given that this spec would be for a Linux container,
	// we expect the Linux section to be present in the spec.
	if spec.Linux == nil {
		return fmt.Errorf("linux section cannot be nil for LCOW container")
	}

	return nil
}
