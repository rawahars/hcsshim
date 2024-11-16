//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/Microsoft/go-winio"
	runhcsopts "github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/options"
	"github.com/Microsoft/hcsshim/internal/appargs"
	lmproto "github.com/Microsoft/hcsshim/internal/lm/proto"
	statepkg "github.com/Microsoft/hcsshim/internal/state"
	"github.com/containerd/ttrpc"
	"github.com/urfave/cli"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"
)

var lmPrepareCommand = cli.Command{
	Name:      "lmprepare",
	Usage:     "Prepares the sandbox for migration",
	ArgsUsage: "[flags] <pipe> <output file>",
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
		address := args[0]

		conn, err := winio.DialPipe(address, nil)
		if err != nil {
			return fmt.Errorf("dial %s: %w", address, err)
		}

		client := ttrpc.NewClient(conn)
		svc := lmproto.NewMigrationClient(client)

		ctx := context.Background()

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
			marshaler = protojson.MarshalOptions{Multiline: true, Indent: "\t", EmitUnpopulated: true}
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
		return nil
	},
}

var lmListenCommand = cli.Command{
	Name:      "lmlisten",
	ArgsUsage: "[flags] <pipe> <ip>",
	Flags: []cli.Flag{
		cli.IntFlag{
			Name: "port",
		},
	},
	SkipArgReorder: true,
	Before:         appargs.Validate(appargs.String, appargs.String),
	Action: func(clictx *cli.Context) error {
		args := clictx.Args()
		address := args[0]

		conn, err := winio.DialPipe(address, nil)
		if err != nil {
			return fmt.Errorf("dial %s: %w", address, err)
		}

		client := ttrpc.NewClient(conn)
		svc := lmproto.NewMigrationClient(client)

		ctx := context.Background()

		var port uint32
		if clictx.IsSet("port") {
			port = uint32(clictx.Int("port"))
		}

		resp, err := svc.ListenChannel(ctx, &lmproto.ListenChannelRequest{
			Ip:   args[1],
			Port: port,
		})
		if err != nil {
			return err
		}
		fmt.Printf("listening on %s:%d\n", args[1], resp.Port)
		return nil
	},
}

var lmAcceptCommand = cli.Command{
	Name:           "lmaccept",
	ArgsUsage:      "[flags] <pipe>",
	SkipArgReorder: true,
	Before:         appargs.Validate(appargs.String),
	Action: func(clictx *cli.Context) error {
		args := clictx.Args()

		address := args[0]

		conn, err := winio.DialPipe(address, nil)
		if err != nil {
			return fmt.Errorf("dial %s: %w", address, err)
		}

		client := ttrpc.NewClient(conn)
		svc := lmproto.NewMigrationClient(client)

		ctx := context.Background()

		if _, err := svc.AcceptChannel(ctx, &lmproto.AcceptChannelRequest{}); err != nil {
			return err
		}
		return nil
	},
}

var lmDialCommand = cli.Command{
	Name:           "lmdial",
	ArgsUsage:      "[flags] <pipe> <ip> <port>",
	SkipArgReorder: true,
	Before:         appargs.Validate(appargs.String, appargs.String, appargs.String),
	Action: func(clictx *cli.Context) error {
		args := clictx.Args()
		address := args[0]

		conn, err := winio.DialPipe(address, nil)
		if err != nil {
			return fmt.Errorf("dial %s: %w", address, err)
		}

		client := ttrpc.NewClient(conn)
		svc := lmproto.NewMigrationClient(client)

		ctx := context.Background()

		port, err := strconv.Atoi(args[2])
		if err != nil {
			return fmt.Errorf("failed parsing port: %w", err)
		}

		if _, err := svc.DialChannel(ctx, &lmproto.DialChannelRequest{
			Ip:   args[1],
			Port: uint32(port),
		}); err != nil {
			return err
		}
		return nil
	},
}

var lmTransferCommand = cli.Command{
	Name:           "lmtransfer",
	ArgsUsage:      "[flags] <pipe>",
	SkipArgReorder: true,
	Before:         appargs.Validate(appargs.String),
	Action: func(clictx *cli.Context) error {
		args := clictx.Args()
		address := args[0]

		conn, err := winio.DialPipe(address, nil)
		if err != nil {
			return fmt.Errorf("dial %s: %w", address, err)
		}

		client := ttrpc.NewClient(conn)
		svc := lmproto.NewMigrationClient(client)

		ctx := context.Background()

		stream, err := svc.TransferSandbox(ctx, &lmproto.TransferSandboxRequest{})
		if err != nil {
			return err
		}
		for {
			msg, err := stream.Recv()
			if err != nil {
				return err
			}
			fmt.Printf("Received status update:\n\tID: %d\n\tStatus: %v\n\tError: %s\n", msg.MessageId, msg.Status, msg.ErrorMessage)
			if msg.Status == lmproto.TransferSandboxResponse_STATUS_CONMPLETE ||
				msg.Status == lmproto.TransferSandboxResponse_STATUS_FAILED ||
				msg.Status == lmproto.TransferSandboxResponse_STATUS_CANCEL {
				break
			}
		}
		return nil
	},
}

var lmFinalizeCommand = cli.Command{
	Name:           "lmfinalize",
	ArgsUsage:      "[flags] <pipe> resume|stop",
	SkipArgReorder: true,
	Before:         appargs.Validate(appargs.String, appargs.String),
	Action: func(clictx *cli.Context) error {
		args := clictx.Args()
		address := args[0]

		conn, err := winio.DialPipe(address, nil)
		if err != nil {
			return fmt.Errorf("dial %s: %w", address, err)
		}

		client := ttrpc.NewClient(conn)
		svc := lmproto.NewMigrationClient(client)

		ctx := context.Background()

		req := &lmproto.FinalizeSandboxRequest{}
		switch args[1] {
		case "resume":
			req.Action = lmproto.FinalizeSandboxRequest_ACTION_RESUME
		case "stop":
			req.Action = lmproto.FinalizeSandboxRequest_ACTION_STOP
		default:
			return fmt.Errorf("bad action, should be resume or stop: %s", args[1])
		}
		if _, err := svc.FinalizeSandbox(ctx, req); err != nil {
			return err
		}
		return nil
	},
}

var jsonPBTypes = map[string]func() protoreflect.ProtoMessage{
	"SandboxLMSpec":          func() protoreflect.ProtoMessage { return &lmproto.SandboxLMSpec{} },
	"ContainerRestoreSpec":   func() protoreflect.ProtoMessage { return &lmproto.ContainerRestoreSpec{} },
	"PrepareSandboxResponse": func() protoreflect.ProtoMessage { return &lmproto.PrepareSandboxResponse{} },
	"TaskServerState":        func() protoreflect.ProtoMessage { return &statepkg.TaskServerState{} },
	"Options":                func() protoreflect.ProtoMessage { return &runhcsopts.Options{} },
	"any":                    func() protoreflect.ProtoMessage { return &anypb.Any{} },
}

var json2pbCommand = cli.Command{
	Name:           "json2pb",
	ArgsUsage:      "<type name> <input file> <output file>",
	SkipArgReorder: true,
	Before:         appargs.Validate(appargs.String, appargs.String, appargs.String),
	Action: func(clictx *cli.Context) error {
		input, err := os.ReadFile(clictx.Args()[1])
		if err != nil {
			return err
		}
		valueCreator := jsonPBTypes[clictx.Args()[0]]
		if valueCreator == nil {
			return fmt.Errorf("unsupported type name: %s", clictx.Args()[0])
		}
		value := valueCreator()
		if err := (protojson.UnmarshalOptions{}).Unmarshal(input, value); err != nil {
			return err
		}
		output, err := proto.MarshalOptions{}.Marshal(value)
		if err != nil {
			return err
		}
		if err := os.WriteFile(clictx.Args()[2], output, 0644); err != nil {
			return err
		}
		return nil
	},
}

var pb2jsonCommand = cli.Command{
	Name:           "pb2json",
	ArgsUsage:      "<type name> <input file> <output file>",
	SkipArgReorder: true,
	Before:         appargs.Validate(appargs.String, appargs.String, appargs.String),
	Action: func(clictx *cli.Context) error {
		input, err := os.ReadFile(clictx.Args()[1])
		if err != nil {
			return err
		}
		valueCreator := jsonPBTypes[clictx.Args()[0]]
		if valueCreator == nil {
			return fmt.Errorf("unsupported type name: %s", clictx.Args()[0])
		}
		value := valueCreator()
		if err := (proto.UnmarshalOptions{}).Unmarshal(input, value); err != nil {
			return err
		}
		output, err := protojson.MarshalOptions{Multiline: true, Indent: "\t", EmitUnpopulated: true}.Marshal(value)
		if err != nil {
			return err
		}
		if err := os.WriteFile(clictx.Args()[2], output, 0644); err != nil {
			return err
		}
		return nil
	},
}
