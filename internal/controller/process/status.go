//go:build windows

package process

import (
	containerdtypes "github.com/containerd/containerd/api/types/task"
)

// Status represents the lifecycle state of a process, backed by the containerd
// task status enum.
type Status containerdtypes.Status

const (
	// StatusUnknown indicates the process state is not known.
	StatusUnknown = Status(containerdtypes.Status_UNKNOWN)
	// StatusCreated indicates the process has been created but not started.
	StatusCreated = Status(containerdtypes.Status_CREATED)
	// StatusRunning indicates the process is running.
	StatusRunning = Status(containerdtypes.Status_RUNNING)
	// StatusStopped indicates the process has stopped.
	StatusStopped = Status(containerdtypes.Status_STOPPED)
)

func (s Status) String() string {
	return containerdtypes.Status(s).String()
}
