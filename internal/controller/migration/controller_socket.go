//go:build windows && lcow

package migration

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"unsafe"

	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/logfields"

	"github.com/containerd/errdefs"
	"golang.org/x/sys/windows"
)

// wsaVersion is the Winsock version requested by [ensureWinsock] (2.2).
const wsaVersion uint32 = 0x0202

// ensureWinsock initializes Winsock for this process. The Go [net] package
// also performs WSAStartup on first use, but [RegisterDuplicateSocket] calls
// [windows.WSASocket] directly via [golang.org/x/sys/windows] and must not
// rely on any other code having touched [net] first. WSAStartup is reference
// counted and idempotent; we deliberately never call WSACleanup so Winsock
// remains initialized for the lifetime of the process.
var ensureWinsock = sync.OnceValue(func() error {
	var data windows.WSAData
	if err := windows.WSAStartup(wsaVersion, &data); err != nil {
		return fmt.Errorf("WSAStartup: %w", err)
	}
	return nil
})

// soConnectTime is the SOL_SOCKET option that returns the seconds the socket
// has been connected, or 0xFFFFFFFF when it is not connected. It is not
// exported by [golang.org/x/sys/windows].
const soConnectTime int32 = 0x700C

// connectTimeNotConnected is the SO_CONNECT_TIME sentinel returned for an
// unconnected socket.
const connectTimeNotConnected uint32 = 0xFFFFFFFF

func (c *Controller) RegisterDuplicateSocket(ctx context.Context, sessionID string, protocolInfo []byte) error {
	if sessionID == "" {
		return fmt.Errorf("session id is required: %w", errdefs.ErrInvalidArgument)
	}

	wantSize := int(unsafe.Sizeof(windows.WSAProtocolInfo{}))
	if len(protocolInfo) < wantSize {
		return fmt.Errorf("protocol info is %d bytes, want at least %d: %w", len(protocolInfo), wantSize, errdefs.ErrInvalidArgument)
	}

	var info windows.WSAProtocolInfo
	if err := binary.Read(bytes.NewReader(protocolInfo), binary.LittleEndian, &info); err != nil {
		return fmt.Errorf("decode WSAProtocolInfo: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.sessionID != sessionID {
		return fmt.Errorf("session id %q does not match active session %q: %w", sessionID, c.sessionID, errdefs.ErrFailedPrecondition)
	}
	// Idempotent: a repeat call for the same session is a no-op once the
	// socket has been adopted.
	if c.state == StateSocketReady && c.dupSocket != 0 {
		return nil
	}
	if c.state != StateExported && c.state != StateDestinationPrepared {
		return fmt.Errorf("register duplicate socket requires state %s or %s (current: %s): %w", StateExported, StateDestinationPrepared, c.state, errdefs.ErrFailedPrecondition)
	}

	if err := ensureWinsock(); err != nil {
		return err
	}

	sock, err := windows.WSASocket(info.AddressFamily, info.SocketType, info.Protocol, &info, 0, 0)
	if err != nil {
		return fmt.Errorf("WSASocket: %w", err)
	}

	// Verify the duplicated handle actually represents a connected socket;
	// HCS will fail the migration if we hand it an unconnected endpoint.
	var connectTime uint32
	optLen := int32(unsafe.Sizeof(connectTime))
	if err := windows.Getsockopt(sock, windows.SOL_SOCKET, soConnectTime, (*byte)(unsafe.Pointer(&connectTime)), &optLen); err != nil {
		_ = windows.Closesocket(sock)
		return fmt.Errorf("getsockopt SO_CONNECT_TIME: %w", err)
	}
	if connectTime == connectTimeNotConnected {
		_ = windows.Closesocket(sock)
		return fmt.Errorf("duplicated socket is not connected: %w", errdefs.ErrFailedPrecondition)
	}

	c.dupSocket = sock
	c.state = StateSocketReady

	log.G(ctx).WithField(logfields.SessionID, sessionID).Info("migration duplicate socket registered")
	return nil
}
