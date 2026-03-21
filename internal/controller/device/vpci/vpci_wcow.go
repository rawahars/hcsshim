//go:build windows && wcow

package vpci

import "context"

// addGuestVPCIDevice notifies the guest about the new device and blocks until
// the required sysfs/device paths are available before workloads use them.
// Not applicable for Windows Guests.
func (m *Manager) addGuestVPCIDevice(_ context.Context, _ string) error {
	return nil
}
