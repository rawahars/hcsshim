//go:build windows

package shim

import (
	"time"

	"github.com/Microsoft/go-winio/pkg/etw"
	"github.com/containerd/ttrpc"
	"github.com/urfave/cli"
)

const (
	// addrFmt is the format of the address used for containerd shim.
	addrFmt = "\\\\.\\pipe\\ProtectedPrefix\\Administrators\\containerd-shim-%s-%s-pipe"

	// gracefulShutdownTimeout is how long to wait for clean-up before just exiting.
	gracefulShutdownTimeout = 3 * time.Second
)

// Shim defines the behavior of a Windows containerd shim.
// Implementations hold the state and specific logic for the runtime.
type Shim interface {
	// Name returns the shim name (e.g., "containerd-shim-runhcs-lcow-v1").
	Name() string

	// RegisterServices allows the shim to register its specific TTRPC services.
	RegisterServices(ctx *cli.Context, server *ttrpc.Server, events Publisher) error

	// ETW returns the ETW configuration or nil if not used.
	ETW() *ETWConfig

	// Done returns a channel that closes when the service wants to shut down.
	Done() <-chan struct{}
}

// ETWConfig holds the ETW provider configuration.
type ETWConfig struct {
	// Name is the ETW provider name.
	Name string
	// Callback is the ETW callback function.
	Callback etw.EnableCallback
}

// shimContext is the internal parsed global configuration from the context.
type shimContext struct {
	// id is parsed from id field in the context.
	id string
	// namespace is parsed from namespace field in the context.
	namespace string
	// address is parsed from address field in the context.
	address string
	// publishBinary is parsed from publish-binary field in the context.
	publishBinary string
}
