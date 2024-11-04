//go:build windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
	runhcsopts "github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/options"
	"github.com/Microsoft/hcsshim/internal/appargs"
	lmproto "github.com/Microsoft/hcsshim/internal/lm/proto"
	statepkg "github.com/Microsoft/hcsshim/internal/state"
	eventtypes "github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/containerd/containerd/api/services/ttrpc/events/v1"
	"github.com/containerd/containerd/api/types"
	"github.com/containerd/ttrpc"
	"github.com/containerd/typeurl/v2"
	"github.com/urfave/cli"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"
)

var createCommand = cli.Command{
	Name:      "create",
	Usage:     "Creates a task",
	ArgsUsage: "[flags] <address> <id> <bundle dir>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "stdin",
			Usage: "Named pipe path",
		},
		cli.StringFlag{
			Name:  "stdout",
			Usage: "Named pipe path",
		},
		cli.StringFlag{
			Name:  "stderr",
			Usage: "Named pipe path",
		},
		cli.BoolFlag{
			Name:  "tty",
			Usage: "Enable terminal mode for task IO",
		},
		cli.StringFlag{
			Name:  "rootfs",
			Usage: "JSON file to read rootfs from",
		},
		cli.StringFlag{
			Name:  "options",
			Usage: "jsonpb file to read shim options from",
		},
	},
	SkipArgReorder: true,
	Before:         appargs.Validate(appargs.String, appargs.String, appargs.String),
	Action: func(clictx *cli.Context) error {
		args := clictx.Args()
		address := args[0]
		id := args[1]

		bundle, err := filepath.Abs(args[2])
		if err != nil {
			return err
		}

		var rootfs []*types.Mount
		if clictx.IsSet("rootfs") {
			data, err := os.ReadFile(clictx.String("rootfs"))
			if err != nil {
				return err
			}
			if err := json.Unmarshal(data, &rootfs); err != nil {
				return err
			}
		}

		var options *anypb.Any
		if clictx.IsSet("options") {
			data, err := os.ReadFile(clictx.String("options"))
			if err != nil {
				return err
			}
			var opts runhcsopts.Options
			if err := (protojson.UnmarshalOptions{}).Unmarshal(data, &opts); err != nil {
				return err
			}
			any, err := typeurl.MarshalAny(&opts)
			if err != nil {
				return err
			}
			options = &anypb.Any{TypeUrl: any.GetTypeUrl(), Value: any.GetValue()}
		}

		conn, err := winio.DialPipe(address, nil)
		if err != nil {
			return fmt.Errorf("dial %s: %w", address, err)
		}

		client := ttrpc.NewClient(conn)
		svc := task.NewTaskClient(client)

		ctx := context.Background()

		{
			resp, err := svc.Create(ctx, &task.CreateTaskRequest{
				ID:       id,
				Bundle:   bundle,
				Rootfs:   rootfs,
				Terminal: clictx.Bool("tty"),
				Stdin:    clictx.String("stdin"),
				Stdout:   clictx.String("stdout"),
				Stderr:   clictx.String("stderr"),
				Options:  options,
			})
			if err != nil {
				return fmt.Errorf("task.Create: %w", err)
			}
			fmt.Printf("task pid is %d\n", resp.Pid)
		}
		return nil
	},
}

var startCommand = cli.Command{
	Name:           "start",
	Usage:          "",
	ArgsUsage:      "[flags] <address> <id>",
	Flags:          []cli.Flag{},
	SkipArgReorder: true,
	Before:         appargs.Validate(appargs.String, appargs.String),
	Action: func(clictx *cli.Context) error {
		args := clictx.Args()
		address := args[0]
		id := args[1]

		conn, err := winio.DialPipe(address, nil)
		if err != nil {
			return fmt.Errorf("dial %s: %w", address, err)
		}

		client := ttrpc.NewClient(conn)
		svc := task.NewTaskClient(client)

		ctx := context.Background()

		{
			resp, err := svc.Start(ctx, &task.StartRequest{
				ID: id,
			})
			if err != nil {
				return fmt.Errorf("task.Start: %w", err)
			}
			fmt.Printf("task pid is %d\n", resp.Pid)
		}
		return nil
	},
}

var pipeCommand = cli.Command{
	Name:           "pipe",
	Usage:          "",
	ArgsUsage:      "[flags] <stdin pipe> <stdout pipe> <stderr pipe>",
	Flags:          []cli.Flag{},
	SkipArgReorder: true,
	Action: func(clictx *cli.Context) error {
		args := clictx.Args()

		f := func(name, pipe string, wg *sync.WaitGroup, copy func(c net.Conn) (int64, error)) {
			defer wg.Done()
			l, err := winio.ListenPipe(pipe, nil)
			if err != nil {
				panic(err)
			}
			fmt.Printf("%s: listening on %s\n", name, pipe)
			c, err := l.Accept()
			if err != nil {
				panic(err)
			}
			fmt.Printf("%s: received connection\n", name)
			n, err := copy(c)
			fmt.Printf("%s: copy completed after %d bytes", name, n)
			if err != nil {
				fmt.Printf(" and error: %s", err)
			}
			fmt.Printf("\n")
		}

		var wg sync.WaitGroup
		if len(args) > 0 {
			wg.Add(1)
			go f("stdin", args[0], &wg, func(c net.Conn) (int64, error) { return io.Copy(c, os.Stdin) })
		}
		if len(args) > 1 {
			wg.Add(1)
			go f("stdout", args[1], &wg, func(c net.Conn) (int64, error) { return io.Copy(os.Stdout, c) })
		}
		if len(args) > 2 {
			wg.Add(1)
			go f("stderr", args[2], &wg, func(c net.Conn) (int64, error) { return io.Copy(os.Stderr, c) })
		}
		wg.Wait()

		return nil
	},
}

type eventsSvc struct {
	m sync.Mutex
}

func (e *eventsSvc) Forward(ctx context.Context, req *events.ForwardRequest) (*emptypb.Empty, error) {
	e.m.Lock()
	defer e.m.Unlock()

	fmt.Printf("[%s][%s]: %s\n", req.Envelope.Timestamp.AsTime().Format(time.RFC3339), req.Envelope.Namespace, req.Envelope.Topic)
	v, err := typeurl.UnmarshalAny(req.Envelope.Event)
	if err != nil {
		fmt.Printf("\tunmarshal failed: %s\n", err)
	}
	switch v := v.(type) {
	case *eventtypes.TaskCreate:
		fmt.Printf("\tContainerID: %s\n", v.ContainerID)
		fmt.Printf("\tBundle: %s\n", v.Bundle)
		fmt.Printf("\tPID: %d\n", v.Pid)
	case *eventtypes.TaskStart:
		fmt.Printf("\tContainerID: %s\n", v.ContainerID)
		fmt.Printf("\tPID: %d\n", v.Pid)
	case *eventtypes.TaskExit:
		fmt.Printf("\tID: %s\n", v.ID)
		fmt.Printf("\tContainerID: %s\n", v.ContainerID)
		fmt.Printf("\tPID: %d\n", v.Pid)
		fmt.Printf("\tExitStatus: %d\n", v.ExitStatus)
		fmt.Printf("\tExitedAt: %v\n", v.ExitedAt.AsTime().Format(time.RFC3339))
	default:
		fmt.Printf("\tunrecognized event type: %T\n", v)
	}
	return &emptypb.Empty{}, nil
}

var eventsCommand = cli.Command{
	Name:           "events",
	Usage:          "",
	ArgsUsage:      "[flags] <address>",
	Flags:          []cli.Flag{},
	SkipArgReorder: true,
	Before:         appargs.Validate(appargs.String),
	Action: func(clictx *cli.Context) error {
		args := clictx.Args()
		address := args[0]

		l, err := winio.ListenPipe(address, nil)
		if err != nil {
			return err
		}

		server, err := ttrpc.NewServer()
		if err != nil {
			return err
		}
		events.RegisterEventsService(server, &eventsSvc{})
		if err := server.Serve(context.Background(), l); err != nil {
			return err
		}
		return nil
	},
}

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

var deleteCommand = cli.Command{
	Name:           "delete",
	ArgsUsage:      "<pipe> <task id>",
	SkipArgReorder: true,
	Before:         appargs.Validate(appargs.String, appargs.String),
	Action: func(clictx *cli.Context) error {
		args := clictx.Args()
		address := args[0]
		id := args[1]

		conn, err := winio.DialPipe(address, nil)
		if err != nil {
			return fmt.Errorf("dial %s: %w", address, err)
		}

		client := ttrpc.NewClient(conn)
		svc := task.NewTaskClient(client)

		ctx := context.Background()

		if _, err := svc.Delete(ctx, &task.DeleteRequest{ID: id}); err != nil {
			return err
		}
		return nil
	},
}

var shutdownCommand = cli.Command{
	Name:           "shutdown",
	ArgsUsage:      "<pipe> <task id>",
	SkipArgReorder: true,
	Before:         appargs.Validate(appargs.String, appargs.String),
	Action: func(clictx *cli.Context) error {
		args := clictx.Args()
		address := args[0]
		id := args[1]

		conn, err := winio.DialPipe(address, nil)
		if err != nil {
			return fmt.Errorf("dial %s: %w", address, err)
		}

		client := ttrpc.NewClient(conn)
		svc := task.NewTaskClient(client)

		ctx := context.Background()

		if _, err := svc.Shutdown(ctx, &task.ShutdownRequest{ID: id}); err != nil {
			return err
		}
		return nil
	},
}
