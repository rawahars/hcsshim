//go:build windows

package drivers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/Microsoft/go-winio/pkg/guid"

	"github.com/Microsoft/hcsshim/internal/cmd"
	"github.com/Microsoft/hcsshim/internal/guestpath"
)

var errNoExecOutput = errors.New("failed to get any pipe output")

// guest is the UVM instance in which the driver will be installed.
type guest interface {
	ExecInUVM(ctx context.Context, request *cmd.CmdProcessRequest) (int, error)
}

// ExecGCSInstallDriver installs a driver into the UVM by running 'install-drivers'
// inside the guest. hostPath is the host VHD path and guestPath is the
// SCSI-mounted location inside the UVM. Returns an error if installation fails,
// along with any stderr output from the guest process.
func ExecGCSInstallDriver(ctx context.Context, guest guest, hostPath string, guestPath string) error {
	driverReadWriteDir, err := getDriverWorkDir(hostPath)
	if err != nil {
		return fmt.Errorf("failed to create a guid path for driver %+v: %w", hostPath, err)
	}

	p, l, err := cmd.CreateNamedPipeListener()
	if err != nil {
		return err
	}
	defer l.Close()

	var stderrOutput string
	errChan := make(chan error)

	go readAllPipeOutput(l, errChan, &stderrOutput)

	args := []string{
		"/bin/install-drivers",
		driverReadWriteDir,
		guestPath,
	}
	req := &cmd.CmdProcessRequest{
		Args:   args,
		Stderr: p,
	}

	// A call to `ExecInUvm` may fail in the following ways:
	// - The process runs and exits with a non-zero exit code. In this case we need to wait on the output
	//   from stderr so we can log it for debugging.
	// - There's an error trying to run the process. No need to wait for stderr logs.
	// - There's an error copying IO. No need to wait for stderr logs.
	//
	// Since we cannot distinguish between the cases above, we should always wait to read the stderr output.
	exitCode, execErr := guest.ExecInUVM(ctx, req)

	// wait to finish parsing stdout results
	select {
	case err := <-errChan:
		if err != nil && !errors.Is(err, errNoExecOutput) {
			return fmt.Errorf("failed to get stderr output from command %s: %w", guestPath, err)
		}
	case <-ctx.Done():
		return fmt.Errorf("timed out waiting for the console output from installing driver %s: %w", guestPath, ctx.Err())
	}

	if execErr != nil {
		return fmt.Errorf("%w: failed to install driver %s in uvm with exit code %d: %v", execErr, guestPath, exitCode, stderrOutput)
	}
	return nil
}

// getDriverWorkDir returns the deterministic guest path used as the overlayfs
// root for a driver installation. 'install-drivers' uses the read-only SCSI VHD
// as the lower layer and uses this directory for the upper, work, and content
// directories, giving depmod/modprobe a writable view.
//
// If the directory already exists, 'install-drivers' skips reinstallation.
// The path is derived from a v5 UUID seeded with the host VHD path,
// ensuring a stable mapping across reboots.
func getDriverWorkDir(hostPath string) (string, error) {
	// 914aadc8-f700-4365-8016-ddad0a9d406d. Random GUID chosen for namespace.
	ns := guid.GUID{
		Data1: 0x914aadc8,
		Data2: 0xf700,
		Data3: 0x4365,
		Data4: [8]byte{0x80, 0x16, 0xdd, 0xad, 0x0a, 0x9d, 0x40, 0x6d},
	}

	driverGUID, err := guid.NewV5(ns, []byte(hostPath))
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(guestpath.LCOWGlobalDriverPrefixFmt, driverGUID.String()), nil
}

// readAllPipeOutput is a helper function that connects to a listener and attempts to
// read the connection's entire output. Resulting output is returned as a string
// in the `result` param. The `errChan` param is used to propagate an errors to
// the calling function.
func readAllPipeOutput(l net.Listener, errChan chan<- error, result *string) {
	defer close(errChan)
	c, err := l.Accept()
	if err != nil {
		errChan <- fmt.Errorf("failed to accept named pipe: %w", err)
		return
	}
	bytes, err := io.ReadAll(c)
	if err != nil {
		errChan <- err
		return
	}

	*result = string(bytes)

	if len(*result) == 0 {
		errChan <- errNoExecOutput
		return
	}

	errChan <- nil
}
