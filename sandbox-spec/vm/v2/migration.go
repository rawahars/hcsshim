package vm

import (
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/containerd/typeurl/v2"
	anypb "google.golang.org/protobuf/types/known/anypb"
)

func init() {
	typeurl.Register(&MigrationSpec{}, "sandbox-spec/vm/v2/MigrationSpec", "MigrationSpec")
}

// MigrationSpec captures the exported configuration of a sandbox during live migration,
// used to transfer state from the source to the destination.
type MigrationSpec struct {
	// Config is the opaque sandbox configuration exported during PrepareAndExportSandbox,
	// to be set in the CreateSandbox input on the destination.
	Config *anypb.Any `json:"config,omitempty"`

	// InitOptions contains the migration initialization options used to configure the
	// HCS compute system on destination.
	InitOptions *hcsschema.MigrationInitializeOptions `json:"init_options,omitempty"`
}
