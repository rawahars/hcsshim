//go:build windows

package driver

type Manager struct {
}

// Ensure Manager implements Controller.
var _ Controller = (*Manager)(nil)
