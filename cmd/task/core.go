//go:build windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/Microsoft/go-winio"
	runhcsopts "github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/options"
	"github.com/Microsoft/hcsshim/internal/appargs"
	"github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/containerd/containerd/api/types"
	"github.com/containerd/ttrpc"
	"github.com/containerd/typeurl/v2"
	"github.com/urfave/cli"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
)

var stateCommand = cli.Command{
	Name: "state",
	Action: func(clictx *cli.Context) error {
		args := clictx.Args()
		address := args[0]
		id := args[1]

		execID := clictx.String("execid")

		conn, err := winio.DialPipe(address, nil)
		if err != nil {
			return fmt.Errorf("dial %s: %w", address, err)
		}

		client := ttrpc.NewClient(conn)
		svc := task.NewTaskClient(client)

		ctx := context.Background()

		resp, err := svc.State(ctx, &task.StateRequest{
			ID:     id,
			ExecID: execID,
		})
		if err != nil {
			return fmt.Errorf("task.Start: %w", err)
		}
		fmt.Printf("Bundle: %s\n", resp.Bundle)
		fmt.Printf("PID: %d\n", resp.Pid)
		fmt.Printf("Status: %v\n", resp.Status)
		fmt.Printf("Stdin: %s\n", resp.Stdin)
		fmt.Printf("Stdout: %s\n", resp.Stdout)
		fmt.Printf("Stderr: %s\n", resp.Stderr)
		fmt.Printf("Terminal: %v\n", resp.Terminal)
		fmt.Printf("ExitStatus: %d\n", resp.ExitStatus)
		fmt.Printf("ExitedAt: %v\n", resp.ExitedAt.AsTime())
		return nil
	},
}

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
		return nil
	},
}

var startCommand = cli.Command{
	Name:      "start",
	Usage:     "",
	ArgsUsage: "[flags] <address> <id>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: "execid",
		},
	},
	SkipArgReorder: true,
	Before:         appargs.Validate(appargs.String, appargs.String),
	Action: func(clictx *cli.Context) error {
		args := clictx.Args()
		address := args[0]
		id := args[1]

		execID := clictx.String("execid")

		conn, err := winio.DialPipe(address, nil)
		if err != nil {
			return fmt.Errorf("dial %s: %w", address, err)
		}

		client := ttrpc.NewClient(conn)
		svc := task.NewTaskClient(client)

		ctx := context.Background()

		resp, err := svc.Start(ctx, &task.StartRequest{
			ID:     id,
			ExecID: execID,
		})
		if err != nil {
			return fmt.Errorf("task.Start: %w", err)
		}
		fmt.Printf("task pid is %d\n", resp.Pid)
		return nil
	},
}

var deleteCommand = cli.Command{
	Name:      "delete",
	ArgsUsage: "<pipe> <task id>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: "execid",
		},
	},
	SkipArgReorder: true,
	Before:         appargs.Validate(appargs.String, appargs.String),
	Action: func(clictx *cli.Context) error {
		args := clictx.Args()
		address := args[0]
		id := args[1]

		execID := clictx.String("execid")

		conn, err := winio.DialPipe(address, nil)
		if err != nil {
			return fmt.Errorf("dial %s: %w", address, err)
		}

		client := ttrpc.NewClient(conn)
		svc := task.NewTaskClient(client)

		ctx := context.Background()

		if _, err := svc.Delete(ctx, &task.DeleteRequest{ID: id, ExecID: execID}); err != nil {
			return err
		}
		return nil
	},
}

var pidsCommand = cli.Command{
	Name:           "pids",
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

		resp, err := svc.Pids(ctx, &task.PidsRequest{ID: id})
		if err != nil {
			return err
		}
		for _, p := range resp.Processes {
			fmt.Printf("%d\n", p.Pid)
		}
		return nil
	},
}

var killCommand = cli.Command{
	Name:      "kill",
	ArgsUsage: "<pipe> <task id> <signal>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: "execid",
		},
		cli.BoolFlag{
			Name: "all",
		},
	},
	SkipArgReorder: true,
	Before:         appargs.Validate(appargs.String, appargs.String, appargs.String),
	Action: func(clictx *cli.Context) error {
		args := clictx.Args()
		address := args[0]
		id := args[1]
		signalStr := args[2]

		signal, err := strconv.Atoi(signalStr)
		if err != nil {
			return err
		}

		execID := clictx.String("execid")

		conn, err := winio.DialPipe(address, nil)
		if err != nil {
			return fmt.Errorf("dial %s: %w", address, err)
		}

		client := ttrpc.NewClient(conn)
		svc := task.NewTaskClient(client)

		ctx := context.Background()

		if _, err := svc.Kill(ctx, &task.KillRequest{
			ID:     id,
			ExecID: execID,
			Signal: uint32(signal),
			All:    clictx.Bool("all"),
		}); err != nil {
			return err
		}
		return nil
	},
}

var execCommand = cli.Command{
	Name:      "exec",
	ArgsUsage: "<pipe> <task id> <exec id> <spec path>",
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
	},
	SkipArgReorder: true,
	Before:         appargs.Validate(appargs.String, appargs.String, appargs.String, appargs.String),
	Action: func(clictx *cli.Context) error {
		args := clictx.Args()
		address := args[0]
		id := args[1]
		execID := args[2]
		specPath := args[3]

		spec, err := os.ReadFile(specPath)
		if err != nil {
			return err
		}

		conn, err := winio.DialPipe(address, nil)
		if err != nil {
			return fmt.Errorf("dial %s: %w", address, err)
		}

		client := ttrpc.NewClient(conn)
		svc := task.NewTaskClient(client)

		ctx := context.Background()

		if _, err := svc.Exec(ctx, &task.ExecProcessRequest{
			ID:       id,
			ExecID:   execID,
			Stdin:    clictx.String("stdin"),
			Stdout:   clictx.String("stdout"),
			Stderr:   clictx.String("stderr"),
			Terminal: clictx.Bool("terminal"),
			Spec:     &anypb.Any{Value: spec},
		}); err != nil {
			return err
		}
		return nil
	},
}

var closeIOCommand = cli.Command{
	Name:      "closeio",
	ArgsUsage: "<pipe> <task id>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: "execid",
		},
		cli.BoolFlag{
			Name: "stdin",
		},
	},
	SkipArgReorder: true,
	Before:         appargs.Validate(appargs.String, appargs.String),
	Action: func(clictx *cli.Context) error {
		args := clictx.Args()
		address := args[0]
		id := args[1]

		execID := clictx.String("execid")

		conn, err := winio.DialPipe(address, nil)
		if err != nil {
			return fmt.Errorf("dial %s: %w", address, err)
		}

		client := ttrpc.NewClient(conn)
		svc := task.NewTaskClient(client)

		ctx := context.Background()

		if _, err := svc.CloseIO(ctx, &task.CloseIORequest{
			ID:     id,
			ExecID: execID,
			Stdin:  clictx.Bool("stdin"),
		}); err != nil {
			return err
		}
		return nil
	},
}

var waitCommand = cli.Command{
	Name:      "wait",
	ArgsUsage: "<pipe> <task id>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: "execid",
		},
	},
	SkipArgReorder: true,
	Before:         appargs.Validate(appargs.String, appargs.String),
	Action: func(clictx *cli.Context) error {
		args := clictx.Args()
		address := args[0]
		id := args[1]

		execID := clictx.String("execid")

		conn, err := winio.DialPipe(address, nil)
		if err != nil {
			return fmt.Errorf("dial %s: %w", address, err)
		}

		client := ttrpc.NewClient(conn)
		svc := task.NewTaskClient(client)

		ctx := context.Background()

		if _, err := svc.Wait(ctx, &task.WaitRequest{
			ID:     id,
			ExecID: execID,
		}); err != nil {
			return err
		}
		return nil
	},
}

var connectCommand = cli.Command{
	Name:           "connect",
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

		if _, err := svc.Connect(ctx, &task.ConnectRequest{ID: id}); err != nil {
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
