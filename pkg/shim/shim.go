//go:build windows

package shim

import (
	"fmt"
	"os"
	"strings"

	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/oc"
	hcsversion "github.com/Microsoft/hcsshim/internal/version"

	"github.com/Microsoft/go-winio/pkg/etw"
	"github.com/Microsoft/go-winio/pkg/etwlogrus"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"go.opencensus.io/trace"

	// register common types spec with typeurl
	_ "github.com/containerd/containerd/v2/core/runtime"
)

const (
	// usage string for the shim executable.
	usage = ``
	// ttrpcAddressEnv is the environment variable used to pass the ttrpc address to the shim.
	ttrpcAddressEnv = "TTRPC_ADDRESS"
)

// Add a manifest to get proper Windows version detection.
//go:generate go run github.com/josephspurrier/goversioninfo/cmd/goversioninfo -platform-specific

// `-ldflags '-X ...'` only works if the variable is uninitialized or set to a constant value.
// keep empty and override with data from [internal/version] only if empty to allow
// workflows currently setting these values to work.
var (
	// version will be the repo version that the binary was built from
	version = ""
	// gitCommit will be the hash that the binary was built from
	gitCommit = ""
)

func Run(shim Shim) {
	logrus.AddHook(log.NewHook())

	// fall back on embedded version info (if any), if variables above were not set
	if version == "" {
		version = hcsversion.Version
	}
	if gitCommit == "" {
		gitCommit = hcsversion.Commit
	}

	// Get the shim name.
	shimName := shim.Name()

	// Configure ETW logging if enabled.
	if etwConfig := shim.ETW(); etwConfig != nil {
		// Provider and hook aren't closed explicitly, as they will exist until process exit.
		provider, err := etw.NewProvider(etwConfig.Name, etwConfig.Callback)
		if err != nil {
			logrus.Error(err)
		} else {
			if hook, err := etwlogrus.NewHookFromProvider(provider); err == nil {
				logrus.AddHook(hook)
			} else {
				logrus.Error(err)
			}
		}

		_ = provider.WriteEvent(
			"ShimLaunched",
			nil,
			etw.WithFields(
				etw.StringField("name", shimName),
				etw.StringArray("Args", os.Args),
				etw.StringField("version", version),
				etw.StringField("commit", gitCommit),
			),
		)

	}

	// Register our OpenCensus logrus exporter
	trace.ApplyConfig(trace.Config{DefaultSampler: oc.DefaultSampler})
	trace.RegisterExporter(&oc.LogrusExporter{})

	app := cli.NewApp()
	app.Name = shimName
	app.Usage = usage

	var v []string
	if version != "" {
		v = append(v, version)
	}
	if gitCommit != "" {
		v = append(v, fmt.Sprintf("commit: %s", gitCommit))
	}
	v = append(v, fmt.Sprintf("spec: %s", specs.Version))
	app.Version = strings.Join(v, "\n")

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "namespace",
			Usage: "the namespace of the container",
		},
		cli.StringFlag{
			Name:  "address",
			Usage: "the address of the containerd's main socket",
		},
		cli.StringFlag{
			Name:  "publish-binary",
			Usage: "the binary path to publish events back to containerd",
		},
		cli.StringFlag{
			Name:  "id",
			Usage: "the id of the container",
		},
		cli.StringFlag{
			Name:  "bundle",
			Usage: "the bundle path to delete (delete command only).",
		},
		cli.BoolFlag{
			Name:  "debug",
			Usage: "run the shim in debug mode",
		},
	}
	app.Commands = []cli.Command{
		getStartCommand(shim),
		getServeCommand(shim),
		getDeleteCommand(shim),
	}
	// In the before stage, we will check if we have the required flags.
	app.Before = func(context *cli.Context) error {
		if namespaceFlag := context.GlobalString("namespace"); namespaceFlag == "" {
			return errors.New("namespace is required")
		}
		if addressFlag := context.GlobalString("address"); addressFlag == "" {
			return errors.New("address is required")
		}
		if containerdBinaryFlag := context.GlobalString("publish-binary"); containerdBinaryFlag == "" {
			return errors.New("publish-binary is required")
		}
		if idFlag := context.GlobalString("id"); idFlag == "" {
			return errors.New("id is required")
		}
		return nil
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(cli.ErrWriter, err)
		os.Exit(1)
	}
}

// parseContext parses the cli context into a shimContext.
func parseContext(ctx *cli.Context) *shimContext {
	return &shimContext{
		namespace:     ctx.GlobalString("namespace"),
		address:       ctx.GlobalString("address"),
		publishBinary: ctx.GlobalString("publish-binary"),
		id:            ctx.GlobalString("id"),
	}
}
