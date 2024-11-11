package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/hcsshim/internal/appargs"
	eventtypes "github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/api/services/ttrpc/events/v1"
	"github.com/containerd/ttrpc"
	"github.com/containerd/typeurl/v2"
	"github.com/urfave/cli"
	"google.golang.org/protobuf/types/known/emptypb"
)

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
