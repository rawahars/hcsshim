package reconn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
)

var (
	errClosed = errors.New("reconn was closed")
)

type Conn interface {
	io.ReadWriteCloser
	CloseRead() error
	CloseWrite() error
}

type Dialer = func(context.Context) (Conn, error)

type Pipe struct {
	d           Dialer
	c           atomic.Value
	backoff     backoff.BackOff
	errFilter   func(err error) bool
	ctx         context.Context // Signals we are closing.
	cancel      func()
	closeOnce   sync.Once
	closeErr    error
	m           sync.Mutex
	readClosed  atomic.Bool
	writeClosed atomic.Bool
}

type intent int

const (
	intentRead intent = iota
	intentWrite
)

func (r *Pipe) File() (*os.File, error) {
	filer, ok := r.c.Load().(interface{ File() (*os.File, error) })
	if !ok {
		return nil, fmt.Errorf("c does not support File")
	}
	return filer.File()
}

func NewPipe(d Dialer, c Conn, backoff backoff.BackOff, errFilter func(err error) bool) *Pipe {
	if c == nil {
		panic("c must be non-nil")
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &Pipe{
		d:         d,
		errFilter: errFilter,
		backoff:   backoff,
		ctx:       ctx,
		cancel:    cancel,
	}
	p.c.Store(c)
	return p
}

func (r *Pipe) Disconnect() error {
	c := r.c.Load().(Conn)
	c.Close()
	go r.reconn(c, 2)
	return nil
}

func (r *Pipe) Read(p []byte) (n int, err error) {
	if r.readClosed.Load() {
		return 0, fmt.Errorf("read is closed")
	}
	c := r.c.Load().(Conn)
	n, err = c.Read(p)
	if err != nil && r.errFilter(err) && !r.writeClosed.Load() {
		err = r.reconn(c, intentRead)
	}
	return n, err
}

func (r *Pipe) Write(p []byte) (n int, err error) {
	if r.writeClosed.Load() {
		return 0, fmt.Errorf("write is closed")
	}
	for {
		c := r.c.Load().(Conn)
		w, err := c.Write(p)
		n += w
		p = p[w:]
		if err != nil && r.errFilter(err) {
			err = r.reconn(c, intentWrite)
		}
		if len(p) == 0 || err != nil {
			return n, err
		}
	}
}

func (r *Pipe) CloseRead() error {
	r.readClosed.Store(true)
	for {
		c := r.c.Load().(Conn)
		err := c.CloseRead()
		if err == nil {
			return nil
		}
		if err != nil && r.errFilter(err) {
			err = r.reconn(c, intentRead)
		}
		if err != nil {
			return err
		}
	}
}

func (r *Pipe) CloseWrite() error {
	r.writeClosed.Store(true)
	for {
		c := r.c.Load().(Conn)
		err := c.CloseWrite()
		if err == nil {
			return nil
		}
		if err != nil && r.errFilter(err) {
			err = r.reconn(c, intentWrite)
		}
		if err != nil {
			return err
		}
	}
}

func (r *Pipe) Close() error {
	r.closeOnce.Do(func() {
		r.cancel()
		r.m.Lock()
		defer r.m.Unlock()
		c := r.c.Load().(Conn)
		r.closeErr = c.Close()
	})
	return r.closeErr
}

func (r *Pipe) closing(i intent) error {
	select {
	case <-r.ctx.Done():
		return errClosed
	default:
	}
	if i == intentRead && r.readClosed.Load() {
		return fmt.Errorf("read closed")
	} else if i == intentWrite && r.writeClosed.Load() {
		return fmt.Errorf("write closed")
	}
	return nil
}

func (r *Pipe) reconn(old Conn, i intent) (err error) {
	r.m.Lock()
	defer r.m.Unlock()
	if r.c.Load() != old {
		return nil
	}
	r.backoff.Reset()
	for {
		d := r.backoff.NextBackOff()
		if err := r.closing(i); err != nil {
			return err
		}
		c, err := r.d(r.ctx)
		if err := r.closing(i); err != nil {
			return err
		}
		if err == nil {
			if r.readClosed.Load() {
				c.CloseRead()
			}
			if r.writeClosed.Load() {
				c.CloseWrite()
			}
			r.c.Store(c)
			return nil
		} else if d == backoff.Stop || !r.errFilter(err) {
			return err
		}
		select {
		case <-time.After(d):
		case <-r.ctx.Done():
			return errClosed
		}
	}
}
