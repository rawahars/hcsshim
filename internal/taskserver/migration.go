package taskserver

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/Microsoft/hcsshim/internal/core"
	lmproto "github.com/Microsoft/hcsshim/internal/lm/proto"
	statepkg "github.com/Microsoft/hcsshim/internal/state"
	"golang.org/x/sys/windows"
	"google.golang.org/protobuf/types/known/anypb"
)

type migrationState struct {
	l windows.Handle
	c windows.Handle
}

var _ (lmproto.MigrationService) = (*service)(nil)

func (s *service) PrepareSandbox(ctx context.Context, req *lmproto.PrepareSandboxRequest) (*lmproto.PrepareSandboxResponse, error) {
	sandboxState, resources, err := s.sandbox.Sandbox.(core.Migratable).LMPrepare(ctx)
	if err != nil {
		return nil, fmt.Errorf("prepare sandbox for migration: %w", err)
	}
	state := &statepkg.TaskServerState{
		Sandbox: sandboxState,
		Tasks:   make(map[string]*statepkg.TaskState),
	}
	state.Tasks[s.sandbox.TaskID] = &statepkg.TaskState{
		TaskId: s.sandbox.TaskID,
		Pid:    s.sandbox.Pid,
	}
	for id, t := range s.sandbox.Tasks {
		state.Tasks[id] = &statepkg.TaskState{
			TaskId:   t.TaskID,
			ExecId:   t.ExecID,
			Terminal: t.Terminal,
			Pid:      t.Pid,
		}
	}
	stateAny, err := anypb.New(state)
	if err != nil {
		return nil, fmt.Errorf("marshal state as any: %w", err)
	}
	var outResources []*lmproto.SourceRootFS
	for _, r := range resources.Layers {
		outResources = append(outResources, &lmproto.SourceRootFS{Id: r.ResourceID, TaskId: r.ContainerID})
	}
	s.migState = &migrationState{}
	return &lmproto.PrepareSandboxResponse{
		Config:    stateAny,
		Resources: outResources,
	}, nil
}

func (s *service) ListenChannel(ctx context.Context, req *lmproto.ListenChannelRequest) (*lmproto.ListenChannelResponse, error) {
	addr, err := netip.ParseAddr(req.Ip)
	if err != nil {
		return nil, err
	}
	l, port, err := listen(addr)
	if err != nil {
		return nil, err
	}
	s.migState.l = l
	return &lmproto.ListenChannelResponse{
		Port: uint32(port),
	}, nil
}

func (s *service) AcceptChannel(ctx context.Context, req *lmproto.AcceptChannelRequest) (*lmproto.AcceptChannelResponse, error) {
	if s.migState.l == 0 {
		return nil, fmt.Errorf("channel must be listening before you can accept a connection")
	}
	c, err := accept(s.migState.l)
	if err != nil {
		return nil, err
	}
	windows.Closesocket(s.migState.l)
	s.migState.l = 0
	s.migState.c = c
	return &lmproto.AcceptChannelResponse{}, nil
}

func (s *service) DialChannel(ctx context.Context, req *lmproto.DialChannelRequest) (*lmproto.DialChannelResponse, error) {
	addr, err := netip.ParseAddr(req.Ip)
	if err != nil {
		return nil, err
	}
	c, err := dial(netip.AddrPortFrom(addr, uint16(req.Port)))
	if err != nil {
		return nil, err
	}
	s.migState.c = c
	return &lmproto.DialChannelResponse{}, nil
}

func (s *service) TransferSandbox(ctx context.Context, req *lmproto.TransferSandboxRequest, stream lmproto.Migration_TransferSandboxServer) error {
	if s.migState.c == 0 {
		return fmt.Errorf("must set up channel before transferring")
	}
	if err := s.sandbox.Sandbox.(core.Migratable).LMTransfer(ctx, uintptr(s.migState.c)); err != nil {
		return err
	}
	return nil
}

func (s *service) FinalizeSandbox(ctx context.Context, req *lmproto.FinalizeSandboxRequest) (*lmproto.FinalizeSandboxResponse, error) {
	if err := s.sandbox.Sandbox.(core.Migratable).LMFinalize(ctx); err != nil {
		return nil, err
	}
	return &lmproto.FinalizeSandboxResponse{}, nil
}

func (s *service) Cancel(ctx context.Context, req *lmproto.CancelRequest) (*lmproto.CancelResponse, error) {
	if s.migState.l != 0 {
		windows.Closesocket(s.migState.l)
	}
	if s.migState.c != 0 {
		windows.Closesocket(s.migState.c)
	}
	s.migState = nil
	return &lmproto.CancelResponse{}, nil
}

func dial(addrPort netip.AddrPort) (_ windows.Handle, err error) {
	conn, err := windows.Socket(windows.AF_INET, windows.SOCK_STREAM, windows.IPPROTO_TCP)
	if err != nil {
		return 0, err
	}
	defer func() {
		if err != nil {
			windows.Closesocket(conn)
		}
	}()
	if err := windows.Connect(conn, &windows.SockaddrInet4{Port: int(addrPort.Port()), Addr: addrPort.Addr().As4()}); err != nil {
		return 0, err
	}
	return conn, nil
}

func listen(addr netip.Addr) (_ windows.Handle, _ uint16, err error) {
	l, err := windows.Socket(windows.AF_INET, windows.SOCK_STREAM, windows.IPPROTO_TCP)
	if err != nil {
		return 0, 0, err
	}
	if err := windows.Bind(l, &windows.SockaddrInet4{Port: 0, Addr: addr.As4()}); err != nil {
		return 0, 0, err
	}
	defer func() {
		if err != nil {
			windows.Closesocket(l)
		}
	}()
	boundAddr, err := windows.Getsockname(l)
	if err != nil {
		return 0, 0, err
	}

	return l, uint16(boundAddr.(*windows.SockaddrInet4).Port), nil
}

func accept(l windows.Handle) (_ windows.Handle, err error) {
	conn, err := windows.Socket(windows.AF_INET, windows.SOCK_STREAM, windows.IPPROTO_TCP)
	if err != nil {
		return 0, err
	}
	defer func() {
		if err != nil {
			windows.Closesocket(conn)
		}
	}()
	if err := windows.Listen(l, 1); err != nil {
		return 0, err
	}
	var buf [64]byte
	var recvd uint32
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(event)
	overlapped := windows.Overlapped{HEvent: event}
	if err := windows.AcceptEx(l, conn, &buf[0], 0, 32, 32, &recvd, &overlapped); err != nil && err != windows.ERROR_IO_PENDING {
		return 0, err
	}
	if _, err := windows.WaitForSingleObject(event, windows.INFINITE); err != nil {
		return 0, err
	}
	return conn, nil
}
