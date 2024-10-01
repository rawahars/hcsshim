//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"

	"github.com/Microsoft/hcsshim/internal/appargs"
	lmproto "github.com/Microsoft/hcsshim/internal/lm/proto"
	"github.com/Microsoft/hcsshim/internal/shimdiag"
	"github.com/urfave/cli"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

var lmPrepareCommand = cli.Command{
	Name:      "lmprepare",
	Usage:     "Prepares the sandbox for migration",
	ArgsUsage: "[flags] <shim name> <output file>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "format",
			Usage: "Can be 'bin' or 'json'",
			Value: "bin",
		},
	},
	SkipArgReorder: true,
	Before:         appargs.Validate(appargs.String, appargs.String),
	Action: func(clictx *cli.Context) error {
		args := clictx.Args()
		shim, err := shimdiag.GetShim(args[0])
		if err != nil {
			return err
		}

		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt)
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			<-ch
			cancel()
		}()
		svc := lmproto.NewMigrationClient(shim)
		resp, err := svc.PrepareSandbox(ctx, &lmproto.PrepareSandboxRequest{})
		if err != nil {
			return err
		}
		var marshaler interface {
			Marshal(protoreflect.ProtoMessage) ([]byte, error)
		}
		switch clictx.String("format") {
		case "bin":
			marshaler = proto.MarshalOptions{}
		case "json":
			marshaler = protojson.MarshalOptions{}
		default:
			return fmt.Errorf("unsupported format: %s", clictx.String("format"))
		}
		output, err := marshaler.Marshal(resp)
		if err != nil {
			return err
		}
		if err := os.WriteFile(args[1], output, 0644); err != nil {
			return err
		}
		return cli.NewExitError(errors.New(""), 0)
	},
}
