//go:build linux
// +build linux

package transport

import (
	"context"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/Microsoft/hcsshim/internal/guest/reconn"
	"github.com/cenkalti/backoff/v4"
	"github.com/linuxkit/virtsock/pkg/vsock"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// VsockTransport is an implementation of Transport which uses vsock
// sockets.
type VsockTransport struct {
	m     sync.Mutex
	conns []*reconn.Pipe
}

var _ Transport = &VsockTransport{}

// Dial accepts a vsock socket port number as configuration, and
// returns an unconnected VsockConnection struct.
func (t *VsockTransport) Dial(port uint32) (Connection, error) {
	logrus.WithFields(logrus.Fields{
		"port": port,
	}).Info("opengcs::VsockTransport::Dial - vsock dial port")

	// HACK: Remove loop when vsock bugs are fixed!
	// Retry 10 times because vsock.Dial can return connection time out
	// due to some underlying kernel bug.
	for i := 0; i < 10; i++ {
		conn, err := vsock.Dial(vsock.CIDHost, port)
		if err == nil {
			return conn, nil
		}
		// If the error was ETIMEDOUT retry, otherwise fail.
		cause := errors.Cause(err)
		if errno, ok := cause.(syscall.Errno); ok && errno == syscall.ETIMEDOUT {
			time.Sleep(100 * time.Millisecond)
			continue
		} else {
			return nil, errors.Wrapf(err, "vsock Dial port (%d) failed", port)
		}
	}
	return nil, fmt.Errorf("failed connecting the VsockConnection: can't connect after 10 attempts")
}

func (t *VsockTransport) DialReconn(port uint32) (NewConnection, error) {
	c, err := t.Dial(port)
	if err != nil {
		return nil, err
	}
	rp := reconn.NewPipe(
		func(ctx context.Context) (reconn.Conn, error) {
			logrus.WithField("port", port).Info("reconnecting port")
			return vsock.Dial(vsock.CIDHost, port)
		},
		c,
		backoff.NewConstantBackOff(5*time.Second),
		func(err error) bool {
			return true
		},
	)
	t.m.Lock()
	t.conns = append(t.conns, rp)
	t.m.Unlock()
	return &connWrapper{rp, t}, nil
}

func (t *VsockTransport) DisconnectReconns() {
	t.m.Lock()
	defer t.m.Unlock()
	for _, conn := range t.conns {
		conn.Disconnect()
	}
}

type connWrapper struct {
	NewConnection
	t *VsockTransport
}

func (cw *connWrapper) File() (*os.File, error) {
	filer, ok := cw.NewConnection.(interface{ File() (*os.File, error) })
	if !ok {
		return nil, fmt.Errorf("NewConnection does not support File")
	}
	return filer.File()
}

// func (w *connWrapper) Close() error {
// 	w.t.m.Lock()
// 	for i, conn := range w.t.conns {
// 		if conn == w.Connection {
// 			w.t.conns = append(w.t.conns[:i], w.t.conns[i+1:]...)
// 		}
// 	}
// 	w.t.m.Unlock()
// 	return w.Connection.Close()
// }
