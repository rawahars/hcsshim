package transport

import (
	"io"
	"os"
)

// Transport is the interface defining a method of transporting data in a
// connection-like way.
// Examples of a Transport implementation could be:
//
//	-Hyper-V socket transport
//	-TCP/IP socket transport
//	-Mocked-out local transport
type Transport interface {
	// Dial takes a port number and returns a connected connection.
	DialReconn(port uint32) (NewConnection, error)
	Dial(port uint32) (Connection, error)
	DisconnectReconns()
}

// Connection is the interface defining a data connection, such as a socket or
// a mocked implementation.
type connection interface {
	io.ReadWriteCloser
	CloseRead() error
	CloseWrite() error
}

type Connection interface {
	connection
	File() (*os.File, error)
}

type NewConnection interface {
	connection
}
