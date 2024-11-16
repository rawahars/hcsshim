package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/hcsshim/internal/appargs"
	"github.com/containerd/console"
	eventtypes "github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/api/services/ttrpc/events/v1"
	"github.com/containerd/ttrpc"
	"github.com/containerd/typeurl/v2"
	"github.com/urfave/cli"
	"google.golang.org/protobuf/types/known/emptypb"
)

type rawConReader struct {
	f *os.File
}

func (r rawConReader) Read(b []byte) (int, error) {
	n, err := syscall.Read(syscall.Handle(r.f.Fd()), b)
	if n == 0 && len(b) != 0 && err == nil {
		// A zero-byte read on a console indicates that the user wrote Ctrl-Z.
		b[0] = 26
		return 1, nil
	}
	return n, err
}

func pipeIO(name string, path string, f interface{}, in bool, wg *sync.WaitGroup) error {
	l, err := winio.ListenPipe(path, nil)
	if err != nil {
		return err
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Printf("%s: listening on %s\n", name, path)
		c, err := l.Accept()
		if err != nil {
			fmt.Printf("%s: connection failed: %s\n", name, err)
			return
		}
		fmt.Printf("%s: received connection\n", name)
		var copy func() (int64, error)
		if in {
			copy = func() (int64, error) { return io.Copy(c, f.(io.Reader)) }
			defer c.Close()
		} else {
			copy = func() (int64, error) { return io.Copy(f.(io.Writer), c) }
		}
		n, err := copy()
		fmt.Printf("%s: copy completed after %d bytes", name, n)
		if err != nil {
			fmt.Printf(" with error: %s", err)
		}
		fmt.Printf("\n")
	}()
	return nil
}

var ioCommand = cli.Command{
	Name:      "io",
	Usage:     "",
	ArgsUsage: "[flags] <pipe base name>",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name: "tty",
		},
	},
	SkipArgReorder: true,
	Before:         appargs.Validate(appargs.String),
	Action: func(clictx *cli.Context) error {
		pipeBase := clictx.Args()[0]

		var stdin io.Reader = os.Stdin
		if clictx.Bool("tty") {
			con, err := console.ConsoleFromFile(os.Stdin)
			if err != nil {
				return err
			}
			if err := con.SetRaw(); err != nil {
				return err
			}
			defer con.Reset()
			stdin = rawConReader{os.Stdin}
		}

		var wg sync.WaitGroup

		stdinPath := filepath.Join(pipeBase, "stdin")
		if err := pipeIO("stdin", stdinPath, stdin, true, &wg); err != nil {
			return err
		}
		stdoutPath := filepath.Join(pipeBase, "stdout")
		if err := pipeIO("stdout", stdoutPath, os.Stdout, false, &wg); err != nil {
			return err
		}
		var stderrPath string
		if !clictx.Bool("tty") {
			stderrPath = filepath.Join(pipeBase, "stderr")
			if err := pipeIO("stderr", stderrPath, os.Stderr, false, &wg); err != nil {
				return err
			}
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
