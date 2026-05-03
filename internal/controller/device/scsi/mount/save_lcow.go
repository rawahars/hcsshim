//go:build windows && lcow

package mount

import scsisave "github.com/Microsoft/hcsshim/internal/controller/device/scsi/save"

// Save returns a snapshot of the mount for live migration. The returned
// [scsisave.MountState] captures the mount config, lifecycle stage,
// reference count, and resolved guest path so the destination can rebind
// containers to the same in-guest mount on resume.
func (m *Mount) Save() *scsisave.MountState {
	return &scsisave.MountState{
		Config: &scsisave.MountConfig{
			ReadOnly:         m.config.ReadOnly,
			Encrypted:        m.config.Encrypted,
			Options:          append([]string(nil), m.config.Options...),
			EnsureFilesystem: m.config.EnsureFilesystem,
			Filesystem:       m.config.Filesystem,
			BlockDev:         m.config.BlockDev,
		},
		State:     scsisave.MountStage(m.state),
		RefCount:  uint32(m.refCount),
		GuestPath: m.guestPath,
	}
}

// Import rehydrates a [Mount] from a previously [Mount.Save]'d snapshot.
// It restores only static state; the parent disk's host/guest interfaces
// are not needed at this layer.
func Import(state *scsisave.MountState, controller, lun uint, partition uint64) *Mount {
	if state == nil {
		return nil
	}

	cfg := Config{Partition: partition}
	if c := state.GetConfig(); c != nil {
		cfg.ReadOnly = c.GetReadOnly()
		cfg.Encrypted = c.GetEncrypted()
		cfg.Options = append([]string(nil), c.GetOptions()...)
		cfg.EnsureFilesystem = c.GetEnsureFilesystem()
		cfg.Filesystem = c.GetFilesystem()
		cfg.BlockDev = c.GetBlockDev()
	}
	return &Mount{
		controller: controller,
		lun:        lun,
		config:     cfg,
		state:      State(state.GetState()),
		refCount:   int(state.GetRefCount()),
		guestPath:  state.GetGuestPath(),
	}
}
