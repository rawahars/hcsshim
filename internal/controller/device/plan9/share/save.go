//go:build windows && lcow

package share

import (
	"github.com/Microsoft/hcsshim/internal/controller/device/plan9/mount"
	plan9save "github.com/Microsoft/hcsshim/internal/controller/device/plan9/save"
)

// Save returns a snapshot of the share for live migration. The returned
// [plan9save.ShareState] captures the share's guest-visible name,
// lifecycle stage, exposed config, and the in-guest mount (if any).
func (s *Share) Save() *plan9save.ShareState {
	out := &plan9save.ShareState{
		Name:  s.name,
		State: plan9save.ShareStage(s.state),
		Config: &plan9save.ShareConfig{
			ReadOnly:     s.config.ReadOnly,
			Restrict:     s.config.Restrict,
			AllowedNames: append([]string(nil), s.config.AllowedNames...),
		},
	}
	if s.mount != nil {
		out.Mount = s.mount.Save()
	}
	return out
}

// Import rehydrates a [Share] from a previously [Share.Save]'d snapshot.
// It restores the share's name, config, lifecycle stage, and any in-guest
// mount; no host/guest interfaces are needed at this layer.
func Import(state *plan9save.ShareState, hostPath string) *Share {
	if state == nil {
		return nil
	}
	cfg := Config{HostPath: hostPath}
	if c := state.GetConfig(); c != nil {
		cfg.ReadOnly = c.GetReadOnly()
		cfg.Restrict = c.GetRestrict()
		cfg.AllowedNames = append([]string(nil), c.GetAllowedNames()...)
	}
	return &Share{
		name:   state.GetName(),
		config: cfg,
		state:  State(state.GetState()),
		mount:  mount.Import(state.GetMount(), state.GetName()),
	}
}
