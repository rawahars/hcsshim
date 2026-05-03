//go:build windows && lcow

package migration

type State int32

const (
	StateIdle State = iota

	StateSourcePrepared
	StateExported

	StateImported

	StateDestinationPrepared

	StateSocketReady

	StateTransferring

	StateCompleted

	StateFailed

	StateTerminal
)

func (s State) String() string {
	switch s {
	case StateIdle:
		return "Idle"
	case StateSourcePrepared:
		return "SourcePrepared"
	case StateExported:
		return "Exported"
	case StateImported:
		return "Imported"
	case StateDestinationPrepared:
		return "DestinationPrepared"
	case StateSocketReady:
		return "SocketReady"
	case StateTransferring:
		return "Transferring"
	case StateCompleted:
		return "Completed"
	case StateFailed:
		return "Failed"
	case StateTerminal:
		return "Terminal"
	default:
		return "Unknown"
	}
}
