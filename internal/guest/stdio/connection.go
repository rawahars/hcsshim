//go:build linux
// +build linux

package stdio

import (
	"io"

	"github.com/Microsoft/hcsshim/internal/guest/transport"
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
		logrus.WithField("port", *settings.StdIn).Info("connecting to stdin port")
		c, err := tport.DialReconn(*settings.StdIn)
		if err != nil {
			return nil, errors.Wrap(err, "failed creating stdin Connection")
		}
		connSet.In = &logConnection{
			con:  c,
			port: *settings.StdIn,
		}
	}
	if settings.StdOut != nil {
		logrus.WithField("port", *settings.StdOut).Info("connecting to stdout port")
		c, err := tport.DialReconn(*settings.StdOut)
		if err != nil {
			return nil, errors.Wrap(err, "failed creating stdout Connection")
		}
		connSet.Out = &logConnection{
			con:  c,
			port: *settings.StdOut,
		}
	}
	if settings.StdErr != nil {
		logrus.WithField("port", *settings.StdErr).Info("connecting to stderr port")
		c, err := tport.DialReconn(*settings.StdErr)
		if err != nil {
			return nil, errors.Wrap(err, "failed creating stderr Connection")
		}

		connSet.Err = &logConnection{
			con:  c,
			port: *settings.StdErr,
		}
	}
	return connSet, nil
}
