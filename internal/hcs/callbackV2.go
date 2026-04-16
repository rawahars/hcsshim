//go:build windows

package hcs

import (
	"sync"
	"syscall"
	"unsafe"

	"github.com/Microsoft/hcsshim/internal/computecore"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

var (
	nextCallbackV2    uintptr
	callbackMapV2     = map[uintptr]*notificationWatcherContextV2{}
	callbackMapLockV2 = sync.RWMutex{}

	notificationWatcherCallbackV2 = syscall.NewCallback(notificationWatcherV2)
)

type notificationWatcherContextV2 struct {
	channels notificationChannelsV2
	systemID string
}

// notificationChannelV2 carries the event data string from LM notifications.
type notificationChannelV2 chan string

type notificationChannelsV2 map[computecore.HCS_EVENT_TYPE]notificationChannelV2

func newLiveMigrationChannels() notificationChannelsV2 {
	channels := make(notificationChannelsV2)
	// Live migration group events (SetupDone, BlackoutStarted, OfflineDone,
	// MigrationDone, TransferInProgress, etc.)
	channels[computecore.HcsEventTypeGroupLiveMigration] = make(notificationChannelV2, 16)
	return channels
}

func closeChannelsV2(channels notificationChannelsV2) {
	for _, c := range channels {
		close(c)
	}
}

// notificationWatcherV2 is the v2 callback function invoked by computecore.dll.
// Signature matches HCS_EVENT_CALLBACK: func(event *HCS_EVENT, context uintptr).
func notificationWatcherV2(eventPtr uintptr, callbackNumber uintptr) uintptr {
	callbackMapLockV2.RLock()
	context := callbackMapV2[callbackNumber]
	callbackMapLockV2.RUnlock()

	if context == nil {
		return 0
	}

	e := (*computecore.Event)(unsafe.Pointer(eventPtr))
	if e == nil {
		return 0
	}

	eventData := ""
	if e.EventData != nil {
		eventData = windows.UTF16PtrToString(e.EventData)
	}

	logrus.WithFields(logrus.Fields{
		"event-type": e.Type.String(),
		"system-id":  context.systemID,
		"event-data": eventData,
	}).Debug("HCS v2 notification")

	if channel, ok := context.channels[e.Type]; ok {
		// Non-blocking send — drop if channel is full to avoid blocking HCS callback thread.
		select {
		case channel <- eventData:
		default:
			logrus.WithFields(logrus.Fields{
				"event-type": e.Type.String(),
				"system-id":  context.systemID,
			}).Warn("HCS v2 notification channel full, dropping event")
		}
	}

	return 0
}
