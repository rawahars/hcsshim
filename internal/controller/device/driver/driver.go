//go:build windows

package driver

import (
	"context"
	"sync"

	"github.com/Microsoft/hcsshim/internal/controller/device/scsi"
	controllervm "github.com/Microsoft/hcsshim/internal/controller/vm"
)

// Manager is the primary implementation of [driver.Controller].
type Manager struct {
	scsiController scsi.Controller

	mu sync.Mutex
	// drivers maps owner -> (share -> struct{}) for O(1) add/remove/lookup.
	drivers map[string]map[string]struct{}
}

func New(vm controllervm.Handle) *Manager {
	return &Manager{
		scsiController: scsi.New(vm),
		drivers:        make(map[string]map[string]struct{}),
	}
}

// Ensure Manager implements Controller.
var _ Controller = (*Manager)(nil)

// Add mounts and installs a driver into the UVM on behalf of owner.
func (m *Manager) Add(ctx context.Context, owner, share string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.drivers[owner] == nil {
		m.drivers[owner] = make(map[string]struct{})
	}
	m.drivers[owner][share] = struct{}{}
	return nil
}

// Remove uninstalls and unmounts a previously added driver from the UVM for owner.
func (m *Manager) Remove(ctx context.Context, owner, share string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.drivers[owner], share)
	if len(m.drivers[owner]) == 0 {
		delete(m.drivers, owner)
	}
	return nil
}

// List returns the host paths of all drivers currently installed in the UVM
// that are owned by owner.
func (m *Manager) List(ctx context.Context, owner string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	shares := m.drivers[owner]
	result := make([]string, 0, len(shares))
	for s := range shares {
		result = append(result, s)
	}
	return result, nil
}
