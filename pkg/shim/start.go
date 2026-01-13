//go:build windows

package shim

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/containerd/containerd/v2/pkg/atomicfile"
	cshim "github.com/containerd/containerd/v2/pkg/shim"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func getStartCommand(shim Shim) cli.Command {
	var startCommand = cli.Command{
		Name: "start",
		Usage: `
This command will launch new shims.

The start command, as well as all binary calls to the shim, has the bundle for the container set as the cwd.

The start command MUST return an address to a shim for containerd to issue API requests for container operations.

The start command can either start a new shim or return an address to an existing shim based on the shim's logic.
`,
		SkipArgReorder: true,
		Action: func(context *cli.Context) (err error) {
			// We cant write anything to stdout/stderr for this cmd.
			logrus.SetOutput(io.Discard)

			// These shims can be used strictly with containerd 2.0+.
			// There can be following scenarios that will launch a shim-
			//
			// 1. Containerd Sandbox Controller calls the Start command to start
			// the sandbox for the pod. All the container create requests will
			// set the SandboxID via `WithSandbox` ContainerOpts. Thereby, the
			// container create request within the pod will be routed directly to the
			// shim without calling the start command again.
			//
			// 2. Containerd.NewTask is used to create a container without setting the sandboxID
			// and therefore, we will launch a new shim to serve the request.
			//
			// NOTE: These shims will not support routing the create request to an existing
			// shim based on annotations like `io.kubernetes.cri.sandbox-id`.
			//

			var (
				pid int
			)

			// Get the shim context values.
			shimCtx := parseContext(context)
			// Construct the address.
			address := fmt.Sprintf(addrFmt, shimCtx.namespace, shimCtx.id)

			// Get the current working directory.
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}

			// While adhering to the newer Sandbox API model, there isn't a
			// case where we need to return an existing shim address.
			// Therefore, we will always start a new shim process here.
			self, err := os.Executable()
			if err != nil {
				return err
			}

			r, w, err := os.Pipe()
			if err != nil {
				return err
			}
			defer r.Close()
			defer w.Close()

			f, err := os.Create(filepath.Join(cwd, "panic.log"))
			if err != nil {
				return err
			}
			defer f.Close()

			args := []string{
				self,
				"--namespace", shimCtx.namespace,
				"--address", shimCtx.address,
				"--publish-binary", shimCtx.publishBinary,
				"--id", shimCtx.id,
				"serve",
				"--socket", address,
			}

			cmd := &exec.Cmd{
				Path:   self,
				Args:   args,
				Env:    os.Environ(),
				Dir:    cwd,
				Stdin:  os.Stdin,
				Stdout: w,
				Stderr: f,
			}

			if err := cmd.Start(); err != nil {
				return err
			}
			w.Close()
			defer func() {
				if err != nil {
					_ = cmd.Process.Kill()
				}
			}()

			// Forward the invocation stderr until the serve command closes it.
			_, err = io.Copy(os.Stderr, r)
			if err != nil {
				return err
			}
			pid = cmd.Process.Pid

			if err := cshim.WritePidFile(filepath.Join(cwd, "shim.pid"), pid); err != nil {
				return err
			}
			if err := writeAddress(filepath.Join(cwd, "address"), address); err != nil {
				return err
			}

			// Write the address to stdout.
			if _, err := fmt.Fprint(os.Stdout, address); err != nil {
				return err
			}
			return nil
		},
	}

	return startCommand
}

// writeAddress writes an address file atomically
func writeAddress(path, address string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	f, err := atomicfile.New(path, 0o644)
	if err != nil {
		return err
	}
	_, err = f.Write([]byte(address))
	if err != nil {
		_ = f.Cancel()
		return err
	}
	return f.Close()
}
