package hcs

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/Microsoft/hcsshim/internal/computecore"
	"golang.org/x/sys/windows"
)

var (
	notificationWatcherCallbackV2 = syscall.NewCallback(notificationWatcherV2)

	nextCallbackV2    uintptr
	callbackMapV2     = map[uintptr]*notificationWatcherContextV2{}
	callbackMapLockV2 = sync.RWMutex{}
	callbackLogFileV2 = sync.Mutex{}
)

type notificationWatcherContextV2 struct {
	systemID  string
	operation string
}

func notificationWatcherV2(eventPtr uintptr, callbackNumber uintptr) uintptr {
	// Read callback context
	callbackMapLockV2.RLock()
	context := callbackMapV2[callbackNumber]
	callbackMapLockV2.RUnlock()

	if context == nil {
		return 0
	}

	// Ensure directory exists
	dir := `C:\temp`
	_ = os.MkdirAll(dir, 0o755)

	// Create a new file per callback invocation
	// Example: C:\temp\hcs_callback_42_20251006_010136.123.json
	filename := fmt.Sprintf(`%s\hcs_callback.json`, dir)

	callbackLogFileV2.Lock()
	// 🔧 Change: open in append mode instead of truncating
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		callbackLogFileV2.Unlock()
		return 0
	}
	defer func() {
		f.Close()
		callbackLogFileV2.Unlock()
	}()

	e := (*computecore.Event)(unsafe.Pointer(eventPtr))
	if e == nil {
		return 0
	}

	//var (
	//	errString     string
	//	operationType = computecore.HcsOperationTypeNone
	//	resultJSON    string
	//)

	// Be defensive in case e.Operation can be nil
	//if e.Type == computecore.HcsEventTypeGroupOperationInfo {
	//	operationType = e.Operation.Type()
	//	if resultJSON, err := e.Operation.Result(); err == nil {
	//		var result hcsResult
	//		if err := json.Unmarshal([]byte(resultJSON), &result); err == nil {
	//			errString = result.ErrorMessage
	//		}
	//	}
	//}

	// Prepare a record to write
	record := struct {
		Timestamp string `json:"timestamp"`
		SystemID  string `json:"systemId"`
		EventType string `json:"eventType"`
		EventData string `json:"eventData"`
		Operation string `json:"operation"`
		//OperationType   string `json:"operationType"`
		//ResultOperation string `json:"resultOperation"`
		//Error           string `json:"errorOperation"`
	}{
		Timestamp: time.Now().Format(time.RFC3339Nano),
		SystemID:  context.systemID,
		EventType: e.Type.String(),
		EventData: windows.UTF16PtrToString(e.EventData),
		Operation: context.operation,
		//OperationType:   operationType.String(),
		//ResultOperation: resultJSON,
		//Error:           errString,
	}

	// Serialize in a readable way
	payload, _ := json.MarshalIndent(record, "", "  ")

	_, _ = f.Write(payload)
	_, _ = f.WriteString("\n")

	return 0
}
