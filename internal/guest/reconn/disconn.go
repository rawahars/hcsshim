package reconn

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type Disconn struct {
	c             net.Conn
	reconn        func() (net.Conn, error)
	cond          *sync.Cond
	disconnecting atomic.Bool
	discCh        chan struct{}
}

func NewDisconn(c net.Conn, reconn func() (net.Conn, error)) *Disconn {
	return &Disconn{
		c:      c,
		reconn: reconn,
		cond:   sync.NewCond(&sync.Mutex{}),
	}
}

func (d *Disconn) Read(p []byte) (int, error) {
	if d.disconnecting.Load() {
		<-d.discCh
	}
	n, err := d.c.Read(p)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		err = nil
	}
	return n, err
}

func (d *Disconn) Write(p []byte) (int, error) {
	var total int
	for {
		n, err := d.singleWrite(p)
		total += n
		p = p[n:]
		// TODO handle close/deadline error
		if err == fmt.Errorf("TODO: close/deadline error") {
			continue
		}
		return total, err
	}
}

func (d *Disconn) singleWrite(p []byte) (int, error) {
	if d.disconnecting.Load() {
		<-d.discCh
	}
	n, err := d.c.Write(p) // TODO handle partial write?
	if errors.Is(err, os.ErrDeadlineExceeded) {
		err = nil
	}
	return n, err
}

func (d *Disconn) Disconnect() {
	d.discCh = make(chan struct{})
	d.disconnecting.Store(true)
	d.c.SetDeadline(time.Now().Add(-time.Second))
	d.c.Close()
}

func (d *Disconn) Reconnect() error {
	c, err := d.reconn()
	if err != nil {
		return err
	}
	d.c = c
	d.disconnecting.Store(false)
	close(d.discCh)
}
