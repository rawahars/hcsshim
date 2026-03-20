//go:build windows && wcow

package scsi

import "context"

// unplugFromGuest is a no-op on Windows guests because Windows handles
// SCSI hot-unplug automatically when the host removes the disk from the VM.
func (m *Manager) unplugFromGuest(_ context.Context, _, _ uint) error {
	return nil
}
