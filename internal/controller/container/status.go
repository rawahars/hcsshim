//go:build windows

package container

// Status represents the lifecycle state of a container.
type Status uint8

const (
	// NotCreated indicates the container has not been created yet.
	NotCreated Status = iota
	// Created indicates the container has been created but not started.
	Created
	// Started indicates the container is running.
	Started
	// Stopped indicates the container has stopped.
	Stopped
)

func (s Status) String() string {
	switch s {
	case NotCreated:
		return "NotCreated"
	case Created:
		return "Created"
	case Started:
		return "Started"
	case Stopped:
		return "Stopped"
	default:
		return "Unknown"
	}
}
