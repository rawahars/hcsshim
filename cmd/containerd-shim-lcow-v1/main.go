//go:build windows

package main

import (
	"github.com/Microsoft/hcsshim/pkg/shim"

	// register common types spec with typeurl
	_ "github.com/containerd/containerd/v2/core/runtime"
)

const (
	// name is the name of lcow shim implementation.
	name = "containerd-shim-lcow-v1"
	// etwProviderName is the ETW provider name for lcow shim.
	etwProviderName = "Microsoft.Virtualization.RunHCSLCOW"
)

func main() {
	shim.Run(&lcowShim{})
}
