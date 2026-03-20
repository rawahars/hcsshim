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
	"github.com/Microsoft/hcsshim/internal/interop"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

var (
	notificationWatcherCallbackV2 = syscall.NewCallback(notificationWatcherV2)

	callbackLogFileV2 = sync.Mutex{}
)

// notificationWatcherV2 is the v2 callback handler registered via HcsSetComputeSystemCallback.
// It dispatches events to notification channels (for waitBackground) and logs LM events.
// Uses the main callbackMap (shared with v1 process callbacks).
func notificationWatcherV2(eventPtr uintptr, callbackNumber uintptr) uintptr {
	e := (*computecore.Event)(unsafe.Pointer(eventPtr))
	if e == nil {
		return 0
	}

	// Look up context from the main callbackMap (shared with v1 process callbacks).
	callbackMapLock.RLock()
	context := callbackMap[callbackNumber]
	callbackMapLock.RUnlock()

	if context == nil {
		return 0
	}

	eventData := ""
	if e.EventData != nil {
		eventData = windows.UTF16PtrToString(e.EventData)
	}

	log := logrus.WithFields(logrus.Fields{
		"event-type": e.Type.String(),
		"system-id":  context.systemID,
	})

	switch e.Type {
	case computecore.HcsEventTypeSystemExited:
		log.Debug("HCS v2 notification: SystemExited")
		if ch, ok := context.channels[hcsNotificationSystemExited]; ok {
			// Try to extract error from event data (HRESULT in result JSON)
			var result error
			if eventData != "" {
				var hcsRes hcsResult
				if json.Unmarshal([]byte(eventData), &hcsRes) == nil && hcsRes.Error < 0 {
					result = interop.Win32FromHresult(uintptr(hcsRes.Error))
				}
			}
			ch <- result
		}

	case computecore.HcsEventTypeServiceDisconnect:
		log.Debug("HCS v2 notification: ServiceDisconnect")
		if ch, ok := context.channels[hcsNotificationServiceDisconnect]; ok {
			ch <- nil
		}

	case computecore.HcsEventTypeOperationCallback:
		// Map operation type to v1 notification channel
		var notif hcsNotification
		opType := computecore.HcsGetOperationType(e.Operation)
		switch opType {
		case computecore.HcsOperationTypeCreate:
			notif = hcsNotificationSystemCreateCompleted
		case computecore.HcsOperationTypeStart:
			notif = hcsNotificationSystemStartCompleted
		case computecore.HcsOperationTypePause:
			notif = hcsNotificationSystemPauseCompleted
		case computecore.HcsOperationTypeResume:
			notif = hcsNotificationSystemResumeCompleted
		case computecore.HcsOperationTypeSave:
			notif = hcsNotificationSystemSaveCompleted
		default:
			log.WithField("operation-type", opType.String()).Debug("HCS v2 notification: OperationCallback (unhandled op type)")
			break
		}
		if notif != hcsNotificationInvalid {
			// Extract error from operation result
			var result error
			if _, opErr := e.Operation.Result(); opErr != nil {
				result = opErr
			}
			log.WithField("operation-type", opType.String()).Debug("HCS v2 notification: OperationCallback")
			if ch, ok := context.channels[notif]; ok {
				ch <- result
			}
		}

	case computecore.HcsEventTypeGroupLiveMigration:
		log.WithField("event-data", eventData).Info("HCS v2 notification: LiveMigration event")
		logLMEventToFile(context.systemID, e.Type, eventData)

	default:
		log.WithField("event-data", eventData).Debug("HCS v2 notification: unhandled event type")
	}

	return 0
}

// logLMEventToFile appends LM events to a diagnostic log file.
func logLMEventToFile(systemID string, eventType computecore.HCS_EVENT_TYPE, eventData string) {
	dir := `C:\temp`
	_ = os.MkdirAll(dir, 0o755)
	filename := fmt.Sprintf(`%s\hcs_callback.json`, dir)

	callbackLogFileV2.Lock()
	defer callbackLogFileV2.Unlock()

	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()

	record := struct {
		Timestamp string `json:"timestamp"`
		SystemID  string `json:"systemId"`
		EventType string `json:"eventType"`
		EventData string `json:"eventData"`
	}{
		Timestamp: time.Now().Format(time.RFC3339Nano),
		SystemID:  systemID,
		EventType: eventType.String(),
		EventData: eventData,
	}

	payload, _ := json.MarshalIndent(record, "", "  ")
	_, _ = f.Write(payload)
	_, _ = f.WriteString("\n")
}
