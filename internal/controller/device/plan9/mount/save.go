//go:build windows && lcow

package mount

import plan9save "github.com/Microsoft/hcsshim/internal/controller/device/plan9/save"

// Save returns a snapshot of the in-guest mount for live migration. The
// returned [plan9save.MountState] captures the read-only flag,
// lifecycle stage, reference count, and resolved guest path needed to
// rebind containers to this mount on resume.
func (m *Mount) Save() *plan9save.MountState {
	return &plan9save.MountState{
		ReadOnly:  m.config.ReadOnly,
		State:     plan9save.MountStage(m.state),
		RefCount:  uint32(m.refCount),
		GuestPath: m.guestPath,
	}
}

// Import rehydrates a [Mount] from a previously [Mount.Save]'d snapshot.
// It restores only static state; the parent share's host/guest interfaces
// are not needed at this layer.
func Import(state *plan9save.MountState, shareName string) *Mount {
	if state == nil {
		return nil
	}
	return &Mount{
		shareName: shareName,
		config:    Config{ReadOnly: state.GetReadOnly()},
		state:     State(state.GetState()),
		refCount:  int(state.GetRefCount()),
		guestPath: state.GetGuestPath(),
	}
}
