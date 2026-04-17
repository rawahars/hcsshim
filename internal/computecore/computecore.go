package computecore

import (
	"fmt"
	"syscall"
	"unsafe"

	_ "github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

//go:generate go run github.com/Microsoft/go-winio/tools/mkwinsyscall -output zsyscall_windows.go computecore.go

// Operations
//sys HcsCreateOperation(context uintptr, callback uintptr) (op HCS_OPERATION) = computecore.HcsCreateOperation
//sys HcsCloseOperation(op HCS_OPERATION) () = computecore.HcsCloseOperation
//sys HcsGetOperationContext(op HCS_OPERATION) (context uintptr) = computecore.HcsGetOperationContext
//sys HcsSetOperationContext(op HCS_OPERATION, context uintptr) (hr error) = computecore.HcsSetOperationContext
//sys HcsGetComputeSystemFromOperation(op HCS_OPERATION) (cs HCS_SYSTEM) = computecore.HcsGetComputeSystemFromOperation
//sys HcsGetProcessFromOperation(op HCS_OPERATION) (proc HCS_PROCESS) = computecore.HcsGetProcessFromOperation
//sys HcsGetOperationType(op HCS_OPERATION) (typ HCS_OPERATION_TYPE) = computecore.HcsGetOperationType
//sys HcsGetOperationId(op HCS_OPERATION) (id uint64) = computecore.HcsGetOperationId
//sys HcsGetOperationResult(op HCS_OPERATION, result **uint16) (hr error) = computecore.HcsGetOperationResult
//sys HcsGetOperationResultAndProcessInfo(op HCS_OPERATION, procInfo *HCS_PROCESS_INFORMATION, result **uint16) (hr error) = computecore.HcsGetOperationResultAndProcessInfo
//sys HcsWaitForOperationResult(op HCS_OPERATION, timeoutMS uint32, result **uint16) (hr error) = computecore.HcsWaitForOperationResult
//sys HcsWaitForOperationResultAndProcessInfo(op HCS_OPERATION, timeoutMS uint32, procInfo *HCS_PROCESS_INFORMATION, result **uint16) (hr error) = computecore.HcsWaitForOperationResultAndProcessInfo
//sys HcsSetOperationCallback(op HCS_OPERATION, context uintptr, callback uintptr) (hr error) = computecore.HcsSetOperationCallback
//sys HcsCancelOperation(op HCS_OPERATION) (hr error) = computecore.HcsCancelOperation
//sys HcsAddResourceToOperation(op HCS_OPERATION, typ HCS_RESOURCE_TYPE, uri string, handle uintptr) (hr error) = computecore.HcsAddResourceToOperation

// Compute systems
//sys HcsCreateComputeSystem(id string, config string, op HCS_OPERATION, sd *windows.SECURITY_DESCRIPTOR, cs *HCS_SYSTEM) (hr error) = computecore.HcsCreateComputeSystem
//sys HcsOpenComputeSystem(id string, access uint32, cs *HCS_SYSTEM) (hr error) = computecore.HcsOpenComputeSystem
//sys HcsCloseComputeSystem(cs HCS_SYSTEM) () = computecore.HcsCloseComputeSystem
//sys HcsStartComputeSystem(cs HCS_SYSTEM, op HCS_OPERATION, options string) (hr error) = computecore.HcsStartComputeSystem
//sys HcsShutDownComputeSystem(cs HCS_SYSTEM, op HCS_OPERATION, options string) (hr error) = computecore.HcsShutDownComputeSystem
//sys HcsTerminateComputeSystem(cs HCS_SYSTEM, op HCS_OPERATION, options string) (hr error) = computecore.HcsTerminateComputeSystem
//sys HcsCrashComputeSystem(cs HCS_SYSTEM, op HCS_OPERATION, options string) (hr error) = computecore.HcsCrashComputeSystem
//sys HcsPauseComputeSystem(cs HCS_SYSTEM, op HCS_OPERATION, options string) (hr error) = computecore.HcsPauseComputeSystem
//sys HcsResumeComputeSystem(cs HCS_SYSTEM, op HCS_OPERATION, options string) (hr error) = computecore.HcsResumeComputeSystem
//sys HcsSaveComputeSystem(cs HCS_SYSTEM, op HCS_OPERATION, options string) (hr error) = computecore.HcsSaveComputeSystem
//sys HcsGetComputeSystemProperties(cs HCS_SYSTEM, op HCS_OPERATION, query string) (hr error) = computecore.HcsGetComputeSystemProperties
//sys HcsModifyComputeSystem(cs HCS_SYSTEM, op HCS_OPERATION, config string, identity uintptr) (hr error) = computecore.HcsModifyComputeSystem
//sys HcsSetComputeSystemCallback(cs HCS_SYSTEM, options HCS_EVENT_OPTIONS, context uintptr, callback uintptr) (hr error) = computecore.HcsSetComputeSystemCallback
//sys HcsEnumerateComputeSystems(query string, op HCS_OPERATION) (hr error) = computecore.HcsEnumerateComputeSystems

// Service
//sys HcsGetServiceProperties(query string, result **uint16) (hr error) = computecore.HcsGetServiceProperties

// Utility
//sys HcsGrantVmAccess(vmID string, path string) (hr error) = computecore.HcsGrantVmAccess

// Live migration
//sys HcsInitializeLiveMigrationOnSource(cs HCS_SYSTEM, op HCS_OPERATION, options string) (hr error) = computecore.HcsInitializeLiveMigrationOnSource
//sys HcsStartLiveMigrationOnSource(cs HCS_SYSTEM, op HCS_OPERATION, options string) (hr error) = computecore.HcsStartLiveMigrationOnSource
//sys HcsStartLiveMigrationTransfer(cs HCS_SYSTEM, op HCS_OPERATION, options string) (hr error) = computecore.HcsStartLiveMigrationTransfer
//sys HcsFinalizeLiveMigration(cs HCS_SYSTEM, op HCS_OPERATION, options string) (hr error) = computecore.HcsFinalizeLiveMigration

type HCS_SYSTEM uintptr
type HCS_PROCESS uintptr
type HCS_OPERATION uintptr

type HCS_PROCESS_INFORMATION struct {
	ProcessId uint32
	_         uint32 // Reserved
	StdInput  windows.Handle
	StdOutput windows.Handle
	StdError  windows.Handle
}

type HCS_OPERATION_TYPE int

const (
	HcsOperationTypeNone HCS_OPERATION_TYPE = -1 + iota
	HcsOperationTypeEnumerate
	HcsOperationTypeCreate
	HcsOperationTypeStart
	HcsOperationTypeShutdown
	HcsOperationTypePause
	HcsOperationTypeResume
	HcsOperationTypeSave
	HcsOperationTypeTerminate
	HcsOperationTypeModify
	HcsOperationTypeGetProperties
	HcsOperationTypeCreateProcess
	HcsOperationTypeSignalProcess
	HcsOperationTypeGetProcessInfo
	HcsOperationTypeGetProcessProperties
	HcsOperationTypeModifyProcess
	HcsOperationTypeCrash
)

func (op HCS_OPERATION_TYPE) String() string {
	switch op {
	case HcsOperationTypeNone:
		return "None"
	case HcsOperationTypeEnumerate:
		return "Enumerate"
	case HcsOperationTypeCreate:
		return "Create"
	case HcsOperationTypeStart:
		return "Start"
	case HcsOperationTypeShutdown:
		return "Shutdown"
	case HcsOperationTypePause:
		return "Pause"
	case HcsOperationTypeResume:
		return "Resume"
	case HcsOperationTypeSave:
		return "Save"
	case HcsOperationTypeTerminate:
		return "Terminate"
	case HcsOperationTypeModify:
		return "Modify"
	case HcsOperationTypeGetProperties:
		return "GetProperties"
	case HcsOperationTypeCreateProcess:
		return "CreateProcess"
	case HcsOperationTypeSignalProcess:
		return "SignalProcess"
	case HcsOperationTypeGetProcessInfo:
		return "GetProcessInfo"
	case HcsOperationTypeGetProcessProperties:
		return "GetProcessProperties"
	case HcsOperationTypeModifyProcess:
		return "ModifyProcess"
	case HcsOperationTypeCrash:
		return "Crash"
	default:
		return fmt.Sprintf("Unknown: %d", op)
	}
}

type HCS_EVENT_TYPE int

const (
	// HcsEventTypeInvalid = 0x00000000
	HcsEventTypeInvalid HCS_EVENT_TYPE = 0x00000000

	// Events for HCS_SYSTEM handles

	HcsEventTypeSystemExited                      HCS_EVENT_TYPE = 0x00000001
	HcsEventTypeSystemCrashInitiated              HCS_EVENT_TYPE = 0x00000002
	HcsEventTypeSystemCrashReport                 HCS_EVENT_TYPE = 0x00000003
	HcsEventTypeSystemRdpEnhancedModeStateChanged HCS_EVENT_TYPE = 0x00000004
	HcsEventTypeSystemSiloJobCreated              HCS_EVENT_TYPE = 0x00000005
	HcsEventTypeSystemGuestConnectionClosed       HCS_EVENT_TYPE = 0x00000006

	// Events for HCS_PROCESS handles

	HcsEventTypeProcessExited HCS_EVENT_TYPE = 0x00010000

	// Common Events

	HcsEventTypeOperationCallback HCS_EVENT_TYPE = 0x01000000
	HcsEventTypeServiceDisconnect HCS_EVENT_TYPE = 0x02000000

	// Event groups (enabled by HCS_EVENT_OPTIONS)

	HcsEventTypeGroupVmLifecycle   HCS_EVENT_TYPE = 0x80000002
	HcsEventTypeGroupLiveMigration HCS_EVENT_TYPE = 0x80000003

	// Events for HCS_OPERATION

	HcsEventTypeGroupOperationInfo HCS_EVENT_TYPE = 0xC0000001
)

func (hn HCS_EVENT_TYPE) String() string {
	switch hn {
	case HcsEventTypeInvalid:
		return "Invalid"

	// System events
	case HcsEventTypeSystemExited:
		return "SystemExited"
	case HcsEventTypeSystemCrashInitiated:
		return "SystemCrashInitiated"
	case HcsEventTypeSystemCrashReport:
		return "SystemCrashReport"
	case HcsEventTypeSystemRdpEnhancedModeStateChanged:
		return "SystemRdpEnhancedModeStateChanged"
	case HcsEventTypeSystemSiloJobCreated:
		return "SystemSiloJobCreated"
	case HcsEventTypeSystemGuestConnectionClosed:
		return "SystemGuestConnectionClosed"

	// Process events
	case HcsEventTypeProcessExited:
		return "ProcessExited"

	// Common events
	case HcsEventTypeOperationCallback:
		return "OperationCallback"
	case HcsEventTypeServiceDisconnect:
		return "ServiceDisconnect"

	// Groups
	case HcsEventTypeGroupVmLifecycle:
		return "GroupVmLifecycle"
	case HcsEventTypeGroupLiveMigration:
		return "GroupLiveMigration"
	case HcsEventTypeGroupOperationInfo:
		return "GroupOperationInfo"

	default:
		return fmt.Sprintf("Unknown: 0x%08X", uint32(hn))
	}
}

type Event struct {
	Type      HCS_EVENT_TYPE
	EventData *uint16
	Operation HCS_OPERATION
}

type HCS_EVENT_OPTIONS int

const (
	HcsEventOptionNone                      HCS_EVENT_OPTIONS = 0
	HcsEventOptionEnableOperationCallbacks  HCS_EVENT_OPTIONS = 1
	HcsEventOptionEnableLiveMigrationEvents HCS_EVENT_OPTIONS = 4
)

type HCS_RESOURCE_TYPE int

const (
	HcsResourceTypeNone HCS_RESOURCE_TYPE = iota
	HcsResourceTypeFile
	HcsResourceTypeJob
	HcsResourceTypeComObject
	HcsResourceTypeSocket
)

func NewOperation(context uintptr) HCS_OPERATION {
	return HcsCreateOperation(context, 0)
}

func (op HCS_OPERATION) Close() {
	HcsCloseOperation(op)
}

func (op HCS_OPERATION) Type() HCS_OPERATION_TYPE {
	return HcsGetOperationType(op)
}

func (op HCS_OPERATION) ID() uint64 {
	return HcsGetOperationId(op)
}

func (op HCS_OPERATION) Result() (string, error) {
	var result *uint16
	if err := HcsGetOperationResult(op, &result); err != nil {
		return "", err
	}
	s, err := convertResult(result)
	if err != nil {
		return "", err
	}
	return s, nil
}

func (op HCS_OPERATION) WaitResult(timeoutMS uint32) (string, error) {
	var result *uint16
	if err := HcsWaitForOperationResult(op, timeoutMS, &result); err != nil {
		return "", err
	}
	s, err := convertResult(result)
	if err != nil {
		return "", err
	}
	return s, nil
}

func convertResult(result *uint16) (string, error) {
	s := windows.UTF16PtrToString(result)
	if _, err := syscall.LocalFree(syscall.Handle(unsafe.Pointer(result))); err != nil {
		return "", err
	}
	return s, nil
}
