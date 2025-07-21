package taskserver

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync"
	"testing"
	"time"
	"unsafe"

	lmproto "github.com/Microsoft/hcsshim/internal/lm/proto"
	"golang.org/x/sys/windows"
)

func TestCreateDuplicateSocket_VariousCases(t *testing.T) {
	type testCase struct {
		name            string
		protocolInfo    func() []byte
		wsasocketFn     func(int32, int32, int32, *windows.WSAProtocolInfo, uint32, uint32) (windows.Handle, error)
		getsockoptFn    func(windows.Handle, int32, int32, *byte, *int32) error
		expectErr       bool
		skipHandleCheck bool
	}

	// Prepare a valid WSAProtocolInfo
	var validInfo windows.WSAProtocolInfo
	validInfo.AddressFamily = windows.AF_INET
	validInfo.SocketType = windows.SOCK_STREAM
	validInfo.Protocol = windows.IPPROTO_TCP
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, validInfo); err != nil {
		t.Fatalf("failed to write protocol info: %v", err)
	}
	serializedValidInfo := buf.Bytes()

	cases := []testCase{
		{
			name: "mocked success",
			protocolInfo: func() []byte {
				return serializedValidInfo
			},
			wsasocketFn: func(af, st, proto int32, pi *windows.WSAProtocolInfo, g, f uint32) (windows.Handle, error) {
				return windows.Handle(1234), nil
			},
			getsockoptFn: func(s windows.Handle, level, optname int32, b *byte, l *int32) error {
				*(*uint32)(unsafe.Pointer(b)) = 0
				return nil
			},
			expectErr: false,
		},
		{
			name: "invalid protocol info (too short)",
			protocolInfo: func() []byte {
				return []byte{1, 2, 3}
			},
			expectErr: true,
		},
		{
			name: "wsasocket fails",
			protocolInfo: func() []byte {
				return serializedValidInfo
			},
			wsasocketFn: func(af, st, proto int32, pi *windows.WSAProtocolInfo, g, f uint32) (windows.Handle, error) {
				return 0, windows.WSAEINVAL
			},
			expectErr: true,
		},
		{
			name: "getsockopt fails",
			protocolInfo: func() []byte {
				return serializedValidInfo
			},
			wsasocketFn: func(af, st, proto int32, pi *windows.WSAProtocolInfo, g, f uint32) (windows.Handle, error) {
				return windows.Handle(5678), nil
			},
			getsockoptFn: func(s windows.Handle, level, optname int32, b *byte, l *int32) error {
				return windows.WSAEINVAL
			},
			expectErr: true,
		},
		{
			name: "real socket duplication success",
			protocolInfo: func() []byte {
				// Create a real socket
				sock, err := windows.WSASocket(windows.AF_INET, windows.SOCK_STREAM, windows.IPPROTO_TCP, nil, 0, windows.WSA_FLAG_OVERLAPPED)
				if err != nil {
					t.Fatalf("WSASocket failed: %v", err)
				}
				defer windows.Closesocket(sock)

				var protoInfo windows.WSAProtocolInfo
				err = windows.WSADuplicateSocket(sock, uint32(windows.GetCurrentProcessId()), &protoInfo)
				if err != nil {
					t.Fatalf("WSADuplicateSocket failed: %v", err)
				}

				buf := new(bytes.Buffer)
				if err := binary.Write(buf, binary.LittleEndian, protoInfo); err != nil {
					t.Fatalf("failed to serialize protocol info: %v", err)
				}
				return buf.Bytes()
			},
			getsockoptFn: func(s windows.Handle, level, optname int32, b *byte, l *int32) error {
				*(*uint32)(unsafe.Pointer(b)) = 0
				return nil
			},
			expectErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &service{migState: &migrationState{}}

			// Patch wsasocket and getsockopt if provided
			origWSASocket := wsasocket
			origGetsockopt := getsockopt
			if tc.wsasocketFn != nil {
				wsasocket = tc.wsasocketFn
			}
			if tc.getsockoptFn != nil {
				getsockopt = tc.getsockoptFn
			}
			defer func() {
				wsasocket = origWSASocket
				getsockopt = origGetsockopt
			}()

			req := &lmproto.CreateDuplicateSocketRequest{
				ProtocolInfo: tc.protocolInfo(),
			}

			resp, err := s.CreateDuplicateSocket(context.Background(), req)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if resp == nil {
					t.Fatal("expected non-nil response")
				}
				if !tc.skipHandleCheck && s.migState.c == 0 {
					t.Fatalf("expected a non-zero socket handle")
				}
			}
		})
	}
}

func TestWaitForChannelReady_VariousCases(t *testing.T) {
	type testCase struct {
		name        string
		setup       func(s *service)
		signalReady func(s *service)
		expectErr   bool
	}

	cases := []testCase{
		{
			name: "already ready",
			setup: func(s *service) {
				s.migState = &migrationState{c: 42}
				s.mCond = sync.NewCond(&s.m)
			},
			signalReady: func(s *service) {},
			expectErr:   false,
		},
		{
			name: "waits then ready",
			setup: func(s *service) {
				s.migState = &migrationState{c: 0}
				s.mCond = sync.NewCond(&s.m)
			},
			signalReady: func(s *service) {
				// Simulate channel becoming ready after a short delay
				time.AfterFunc(100*time.Millisecond, func() {
					s.m.Lock()
					s.migState.c = 99
					s.mCond.Broadcast()
					s.m.Unlock()
				})
			},
			expectErr: false,
		},
		{
			name: "timeout",
			setup: func(s *service) {
				s.migState = &migrationState{c: 0}
				s.mCond = sync.NewCond(&s.m)
			},
			signalReady: func(s *service) {
				// Never signal ready, should timeout
			},
			expectErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &service{}
			tc.setup(s)

			ctx := context.Background()
			if tc.name == "timeout" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 150*time.Millisecond)
				defer cancel()
			}

			done := make(chan struct{})
			var err error
			go func() {
				tc.signalReady(s)
				_, err = s.WaitForChannelReady(ctx, &lmproto.WaitForChannelReadyRequest{})
				close(done)
			}()

			select {
			case <-done:
				if tc.expectErr && err == nil {
					t.Fatalf("expected error but got nil")
				}
				if !tc.expectErr && err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			case <-time.After(1 * time.Second):
				t.Fatal("test timed out")
			}
		})
	}
}
