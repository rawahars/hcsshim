//go:build windows
// +build windows

package bridge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sync"

	"github.com/pkg/errors"
	"golang.org/x/sys/windows"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Microsoft/hcsshim/internal/guest/gcserr"
	"github.com/Microsoft/hcsshim/internal/guest/prot"
	"github.com/Microsoft/hcsshim/pkg/securitypolicy"
	windowssecuritypolicy "github.com/Microsoft/hcsshim/pkg/securitypolicy"
)

// TODO:
// - Test different error cases
// - Add spans, bridge.Log()

type Bridge struct {
	mu        sync.Mutex
	hostState *Host
	// List of handlers for handling different rpc message requests.
	rpcHandlerList map[rpcProc]HandlerFunc

	// hcsshim and inbox GCS connections respectively.
	shimConn     io.ReadWriteCloser
	inboxGCSConn io.ReadWriteCloser

	// Response channels to forward incoming requests to inbox GCS
	// and send responses back to hcsshim respectively.
	sendToGCSCh  chan request
	sendToShimCh chan bridgeResponse
}

type bridgeResponse struct {
	ctx      context.Context
	header   MessageHeader
	response []byte
}

type request struct {
	// Context created once received from the bridge.
	ctx context.Context
	// header is the wire format message header that preceded the message for
	// this request.
	header MessageHeader
	// activityID is the id of the specific activity for this request.
	activityID guid.GUID
	// message is the portion of the request that follows the `Header`.
	message []byte
}

func NewBridge(shimConn io.ReadWriteCloser, inboxGCSConn io.ReadWriteCloser, initialEnforcer securitypolicy.SecurityPolicyEnforcer) *Bridge {
	hostState := NewHost(initialEnforcer)
	return &Bridge{
		rpcHandlerList: make(map[rpcProc]HandlerFunc),
		hostState:      hostState,
		shimConn:       shimConn,
		inboxGCSConn:   inboxGCSConn,
		sendToGCSCh:    make(chan request),
		sendToShimCh:   make(chan bridgeResponse),
	}
}

func NewPolicyEnforcer(initialEnforcer windowssecuritypolicy.SecurityPolicyEnforcer) *SecurityPoliyEnforcer {
	return &SecurityPoliyEnforcer{
		securityPolicyEnforcerSet: false,
		securityPolicyEnforcer:    initialEnforcer,
	}
}

// UnknownMessage represents the default handler logic for an unmatched request
// type sent from the bridge.
func UnknownMessage(r *request) error {
	log.Printf("unknown handler with rpcMessage type %v", msgType(r.header.Type).String())
	return gcserr.WrapHresult(errors.Errorf("bridge: function not supported, header type: %v", r.header.Type), gcserr.HrNotImpl)
}

// HandlerFunc is an adapter to use functions as handlers.
type HandlerFunc func(*request) error

// ServeMsg serves request by calling appropriate handler functions.
func (b *Bridge) ServeMsg(r *request) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if r == nil {
		panic("bridge: nil request to handler")
	}

	var handler HandlerFunc
	var ok bool
	messageType := r.header.Type
	rpcProcID := rpcProc(msgType(messageType) &^ msgTypeMask)
	if handler, ok = b.rpcHandlerList[rpcProcID]; !ok {
		return UnknownMessage(r)
	}

	return handler(r)
}

// Handle registers the handler for the given message id and protocol version.
func (b *Bridge) Handle(rpcProcID rpcProc, handlerFunc HandlerFunc) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if handlerFunc == nil {
		panic("empty function handler")
	}

	if _, ok := b.rpcHandlerList[rpcProcID]; ok {
		log.Printf("gcs-sidecar::bridge - overwriting bridge handler. message-type: %v", rpcProcID.String())
	}

	b.rpcHandlerList[rpcProcID] = handlerFunc
}

func (b *Bridge) HandleFunc(rpcProcID rpcProc, handler func(*request) error) {
	if handler == nil {
		panic("bridge: nil handler func")
	}

	b.Handle(rpcProcID, HandlerFunc(handler))
}

// AssignHandlers creates and assigns appropriate event handlers
// for the different bridge message types.
func (b *Bridge) AssignHandlers() {
	b.HandleFunc(rpcCreate, b.createContainer)
	b.HandleFunc(rpcStart, b.startContainer)
	b.HandleFunc(rpcShutdownGraceful, b.shutdownGraceful)
	b.HandleFunc(rpcShutdownForced, b.shutdownForced)
	b.HandleFunc(rpcExecuteProcess, b.executeProcess)
	b.HandleFunc(rpcWaitForProcess, b.waitForProcess)
	b.HandleFunc(rpcSignalProcess, b.signalProcess)
	b.HandleFunc(rpcResizeConsole, b.resizeConsole)
	b.HandleFunc(rpcGetProperties, b.getProperties)
	b.HandleFunc(rpcModifySettings, b.modifySettings)
	b.HandleFunc(rpcNegotiateProtocol, b.negotiateProtocol)
	b.HandleFunc(rpcDumpStacks, b.dumpStacks)
	b.HandleFunc(rpcDeleteContainerState, b.deleteContainerState)
	b.HandleFunc(rpcUpdateContainer, b.updateContainer)
	b.HandleFunc(rpcLifecycleNotification, b.lifecycleNotification)
}

// readMessage reads the message from io.Reader
func readMessage(r io.Reader) (MessageHeader, []byte, error) {
	var h [hdrSize]byte
	_, err := io.ReadFull(r, h[:])
	if err != nil {
		return MessageHeader{}, nil, err
	}
	var header MessageHeader
	buf := bytes.NewReader(h[:])
	err = binary.Read(buf, binary.LittleEndian, &header)
	if err != nil {
		log.Fatalf("error reading message header: %v", err)
		return MessageHeader{}, nil, err
	}

	n := header.Size
	if n < hdrSize || n > maxMsgSize {
		log.Printf("invalid message size %d", n)
		return MessageHeader{}, nil, fmt.Errorf("invalid message size %d", n)
	}

	n -= hdrSize
	msg := make([]byte, n)
	_, err = io.ReadFull(r, msg)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return MessageHeader{}, nil, err
	}

	return header, msg, nil
}

func isLocalDisconnectError(err error) bool {
	return errors.Is(err, windows.WSAECONNABORTED)
}

// Sends request to the inbox GCS channel
func (b *Bridge) forwardRequestToGcs(req *request) {
	b.sendToGCSCh <- *req
}

// Sends response to the hcsshim channel
func (b *Bridge) sendResponseToShim(rpcProcType rpcProc, id SequenceID, response interface{}) error {
	respType := msgTypeResponse | msgType(rpcProcType)
	msgb, err := json.Marshal(response)
	if err != nil {
		return err
	}
	msgHeader := MessageHeader{
		Type: respType,
		Size: uint32(len(msgb) + hdrSize),
		ID:   id,
	}

	b.sendToShimCh <- bridgeResponse{
		//ctx
		header:   msgHeader,
		response: msgb,
	}
	return nil
}

// ListenAndServeShimRequests listens to messages on the hcsshim
// and inbox GCS connections and schedules them for processing.
// After processing, messages are forwarded to inbox GCS on success
// and responses from inbox GCS or error messages are sent back
// to hcsshim via bridge connection.
func (b *Bridge) ListenAndServeShimRequests() error {
	shimRequestChan := make(chan request)
	shimErrChan := make(chan error)

	defer b.inboxGCSConn.Close()
	defer close(shimRequestChan)
	defer close(shimErrChan)
	defer b.shimConn.Close()
	defer close(b.sendToShimCh)
	defer close(b.sendToGCSCh)

	// Listen to requests from hcsshim
	go func() {
		var recverr error
		br := bufio.NewReader(b.shimConn)
		for {
			header, msg, err := readMessage(br)
			if err != nil {
				if err == io.EOF || isLocalDisconnectError(err) {
					return
				}
				log.Printf("bridge read from shim connection failed: %s \n", err)
				recverr = errors.Wrap(err, "bridge read from shim connection failed")
				break
			}
			var msgBase requestBase
			_ = json.Unmarshal(msg, &msgBase)
			req := request{
				ctx:        context.Background(),
				activityID: msgBase.ActivityID,
				header:     header,
				message:    msg,
			}
			log.Printf("Request from shim: \n Header {Type: %v Size: %v ID: %v }\n msg: %v \n", req.header.Type, req.header.Size, req.header.ID, string(req.message))
			shimRequestChan <- req
		}
		shimErrChan <- recverr
	}()
	// Process each bridge request received from shim asynchronously.
	go func() {
		for req := range shimRequestChan {
			go func(req request) {
				if err := b.ServeMsg(&req); err != nil {
					// In case of error, create appropriate response message to
					// be sent to hcsshim.
					resp := &prot.MessageResponseBase{
						Result:       int32(windows.ERROR_GEN_FAILURE),
						ErrorMessage: err.Error(),
						ActivityID:   req.activityID.String(),
					}
					prot.SetErrorForResponseBase(resp, err, "gcs-sidecar" /* moduleName */)
					b.sendResponseToShim(rpcProc(msgTypeResponse), req.header.ID, resp)
					return
				}
			}(req)
		}
	}()
	go func() {
		var err error
		for req := range b.sendToGCSCh {
			// Forward message to gcs
			log.Printf("bridge send to gcs, req %v", req)
			buffer := b.prepareResponseMessage(req.header, req.message)
			_, err := buffer.WriteTo(b.inboxGCSConn)
			if err != nil {
				log.Printf("err sending response to inbox GCS: %v", err)
				err = fmt.Errorf("err forwarding shim req to inbox GCS: %v", err)
				break
			}
		}
		shimErrChan <- err
	}()
	// Receive response from gcs and forward to hcsshim
	go func() {
		var recverr error
		for {
			header, message, err := readMessage(b.inboxGCSConn)
			if err != nil {
				if err == io.EOF || isLocalDisconnectError(err) {
					return
				}
				recverr = fmt.Errorf("bridge read from gcs failed: %s", err)
				log.Printf("bridge read from gcs failed: %v", err)
				break
			}

			// Forward to shim
			resp := bridgeResponse{
				ctx:      context.Background(), //TODO
				header:   header,
				response: message,
			}
			b.sendToShimCh <- resp
		}
		shimErrChan <- recverr
	}()

	go func() {
		var sendErr error
		for resp := range b.sendToShimCh {
			// Send response to shim
			log.Printf("Send response to shim \n Header:{ID: %v, Type: %v, Size: %v} \n msg: %v \n", resp.header.ID,
				resp.header.Type, resp.header.Size, string(resp.response))
			buffer := b.prepareResponseMessage(resp.header, resp.response)
			_, sendErr = buffer.WriteTo(b.shimConn)
			if sendErr != nil {
				log.Printf("err sending response to shim: %v", sendErr)
				sendErr = fmt.Errorf("err sendign response to shim: %v", sendErr)
				break
			}
		}
		shimErrChan <- sendErr
	}()

	select {
	case err := <-shimErrChan:
		return err
	}
}

// Prepare response message
func (b *Bridge) prepareResponseMessage(header MessageHeader, message []byte) bytes.Buffer {
	// Create a buffer to hold the serialized header data
	var headerBuf bytes.Buffer
	err := binary.Write(&headerBuf, binary.LittleEndian, header)
	if err != nil {
		log.Fatal(err)
	}

	// Write message header followed by actual payload.
	var buf bytes.Buffer
	buf.Write(headerBuf.Bytes())
	buf.Write(message[:])
	return buf
}
