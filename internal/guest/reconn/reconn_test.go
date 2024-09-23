package reconn

import (
	"io"
	"testing"
)

type notImplConn struct {
	t *testing.T
}

func (c *notImplConn) Read(p []byte) (int, error) {
	c.t.Fatal("not implemented")
	return 0, nil
}

func (c *notImplConn) Write(p []byte) (int, error) {
	c.t.Fatal("not implemented")
	return 0, nil
}

func (c *notImplConn) CloseRead() error {
	c.t.Fatal("not implemented")
	return nil
}

func (c *notImplConn) CloseWrite() error {
	c.t.Fatal("not implemented")
	return nil
}

func (c *notImplConn) Close() error {
	c.t.Fatal("not implemented")
	return nil
}

type reader struct {
	notImplConn
	c io.ReadCloser
}

func (c *reader) Read(p []byte) (int, error) {
	return c.c.Read(p)
}

func (c *reader) Close() error {
	return c.c.Close()
}

type writer struct {
	notImplConn
	c io.WriteCloser
}

func (c *writer) Write(p []byte) (int, error) {
	return c.c.Write(p)
}

func (c *writer) Close() error {
	return c.c.Close()
}

func newConns(t *testing.T) (Conn, Conn) {
	r, w := io.Pipe()
	return &reader{notImplConn: notImplConn{t}, c: r}, &writer{notImplConn: notImplConn{t}, c: w}
}

func TestReconn(t *testing.T) {
	// var output [][]byte
	// rp := NewPipe()
	// var r reader
}
