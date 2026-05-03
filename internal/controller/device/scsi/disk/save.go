//go:build windows && (lcow || wcow)

package disk

import (
	"github.com/Microsoft/hcsshim/internal/controller/device/scsi/mount"
	scsisave "github.com/Microsoft/hcsshim/internal/controller/device/scsi/save"
)

// Save returns a snapshot of the disk for live migration. The returned
// [scsisave.DiskState] captures the attach config, lifecycle stage,
// and the per-partition mount state needed to re-establish in-guest
// mounts on the destination.
func (d *Disk) Save() *scsisave.DiskState {
	out := &scsisave.DiskState{
		Config: &scsisave.DiskConfig{
			HostPath: d.config.HostPath,
			ReadOnly: d.config.ReadOnly,
			Type:     string(d.config.Type),
			EvdType:  d.config.EVDType,
		},
		State: scsisave.DiskStage(d.state),
	}
	if len(d.mounts) > 0 {
		out.Mounts = make(map[uint64]*scsisave.MountState, len(d.mounts))
		for partition, m := range d.mounts {
			out.Mounts[partition] = m.Save()
		}
	}
	return out
}

// Import rehydrates a [Disk] from a previously [Disk.Save]'d snapshot. It
// restores the attach config, lifecycle stage, and per-partition mount state;
// no host/guest interfaces are needed at this layer.
func Import(state *scsisave.DiskState, controller, lun uint) *Disk {
	if state == nil {
		return nil
	}
	cfg := Config{}
	if c := state.GetConfig(); c != nil {
		cfg = Config{
			HostPath: c.GetHostPath(),
			ReadOnly: c.GetReadOnly(),
			Type:     Type(c.GetType()),
			EVDType:  c.GetEvdType(),
		}
	}
	d := &Disk{
		controller: controller,
		lun:        lun,
		config:     cfg,
		state:      State(state.GetState()),
		mounts:     make(map[uint64]*mount.Mount, len(state.GetMounts())),
	}
	for partition, ms := range state.GetMounts() {
		m := mount.Import(ms, controller, lun, partition)
		if m == nil {
			continue
		}
		d.mounts[partition] = m
	}
	return d
}

// UpdateHostPath rewrites the host-side path of the disk image.
func (d *Disk) UpdateHostPath(p string) {
	d.config.HostPath = p
}
