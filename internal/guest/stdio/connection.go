//go:build linux
// +build linux

package stdio

import (
	"context"
	"io"
	"time"

	"github.com/Microsoft/hcsshim/internal/guest/reconn"
	"github.com/Microsoft/hcsshim/internal/guest/transport"
	"github.com/cenkalti/backoff/v4"
	"github.com/linuxkit/virtsock/pkg/vsock"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type Conn interface {
	io.ReadWriteCloser
	CloseRead() error
	CloseWrite() error
}

// ConnectionSettings describe the stdin, stdout, stderr ports to connect the
// transport to. A nil port specifies no connection.
type ConnectionSettings struct {
	StdIn  *uint32
	StdOut *uint32
	StdErr *uint32
}

type logConnection struct {
	con  Conn
	port uint32
}

func (lc *logConnection) Read(b []byte) (int, error) {
	return lc.con.Read(b)
}

func (lc *logConnection) Write(b []byte) (int, error) {
	return lc.con.Write(b)
}

func (lc *logConnection) Close() error {
	logrus.WithFields(logrus.Fields{
		"port": lc.port,
	}).Debug("opengcs::logConnection::Close - closing connection")

	return lc.con.Close()
}

func (lc *logConnection) CloseRead() error {
	logrus.WithFields(logrus.Fields{
		"port": lc.port,
	}).Debug("opengcs::logConnection::Close - closing read connection")

	return lc.con.CloseRead()
}

func (lc *logConnection) CloseWrite() error {
	logrus.WithFields(logrus.Fields{
		"port": lc.port,
	}).Debug("opengcs::logConnection::Close - closing write connection")

	return lc.con.CloseWrite()
}

var _ = (Conn)(&logConnection{})

// Connect returns new transport.Connection instances, one for each stdio pipe
// to be used. If CreateStd*Pipe for a given pipe is false, the given Connection
// is set to nil.
func Connect(tport transport.Transport, settings ConnectionSettings) (_ *ConnectionSet, err error) {
	connSet := &ConnectionSet{}
	defer func() {
		if err != nil {
			connSet.Close()
		}
	}()
	if settings.StdIn != nil {
		port := *settings.StdIn
		c, err := tport.Dial(port)
		if err != nil {
			return nil, errors.Wrap(err, "failed creating stdin Connection")
		}
		rp := reconn.NewPipe(
			func(ctx context.Context) (reconn.Conn, error) {
				logrus.Info("redialing stdin")
				return vsock.Dial(vsock.CIDHost, port)
			},
			c,
			backoff.NewConstantBackOff(5*time.Second),
			func(err error) bool {
				logrus.Infof("stdin disconnected with %s", err)
				return true
			},
		)
		connSet.In = &logConnection{
			con:  rp,
			port: *settings.StdIn,
		}
	}
	if settings.StdOut != nil {
		port := *settings.StdOut
		c, err := tport.Dial(port)
		if err != nil {
			return nil, errors.Wrap(err, "failed creating stdout Connection")
		}
		rp := reconn.NewPipe(
			func(ctx context.Context) (reconn.Conn, error) {
				logrus.Info("redialing stdout")
				return vsock.Dial(vsock.CIDHost, port)
			},
			c,
			backoff.NewConstantBackOff(5*time.Second),
			func(err error) bool {
				logrus.Infof("stdout disconnected with %s", err)
				return true
			},
		)
		connSet.Out = &logConnection{
			con:  rp,
			port: *settings.StdOut,
		}
	}
	if settings.StdErr != nil {
		port := *settings.StdErr
		c, err := tport.Dial(port)
		if err != nil {
			return nil, errors.Wrap(err, "failed creating stderr Connection")
		}
		rp := reconn.NewPipe(
			func(ctx context.Context) (reconn.Conn, error) {
				logrus.Info("redialing stderr")
				return vsock.Dial(vsock.CIDHost, port)
			},
			c,
			backoff.NewConstantBackOff(5*time.Second),
			func(err error) bool {
				logrus.Infof("stderr disconnected with %s", err)
				return true
			},
		)
		connSet.Err = &logConnection{
			con:  rp,
			port: *settings.StdErr,
		}
	}
	return connSet, nil
}
