package scsi

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"sync"

	"github.com/Microsoft/hcsshim/internal/state"
	"github.com/sirupsen/logrus"
)

type MountManager struct {
	m       sync.Mutex
	mounter mounter
	// Tracks current mounts. Entries will be nil if the mount was unmounted, meaning the index is
	// available for use.
	mounts   []*mount
	mountFmt string
}

func NewMountManager(mounter mounter, mountFmt string) *MountManager {
	return &MountManager{
		mounter:  mounter,
		mountFmt: mountFmt,
	}
}

type mount struct {
	path       string
	index      int
	controller uint
	lun        uint
	config     *MountConfig
	waitErr    error
	waitCh     chan struct{}
	refCount   uint
}

type MountConfig struct {
	Partition       uint64
	ReadOnly        bool
	Encrypted       bool
	Options         []string
	EnsureFileystem bool
	Filesystem      string
}

func (mm *MountManager) UnmountByControllerLun(ctx context.Context, controller, lun uint) error {
	mm.m.Lock()
	defer mm.m.Unlock()
	logrus.Infof("UnmountByControllerLun: unmounting controller %d lun %d", controller, lun)

	for _, mount := range mm.mounts {
		logrus.Infof("UnmountByControllerLun: current mounts: %+v", mm.mounts)
		if mount != nil && mount.controller == controller && mount.lun == lun {
			logrus.Infof("UnmountByControllerLun: current controller: %d, lun: %d", mount.controller, mount.lun)
			mount.refCount--
			if mount.refCount > 0 {
				logrus.Infof("UnmountByControllerLun: refCount for controller %d lun %d is still %d, not unmounting", controller, lun, mount.refCount)
				return nil
			}
			logrus.Infof("UnmountByControllerLun: unmounting controller %d lun %d at path %s", controller, lun, mount.path)
			if err := mm.mounter.unmount(ctx, mount.controller, mount.lun, mount.path, mount.config); err != nil {
				logrus.Errorf("UnmountByControllerLun: error unmounting controller %d lun %d at path %s: %v", mount.controller, mount.lun, mount.path, err)
				return fmt.Errorf("unmount scsi controller %d lun %d at path %s: %w", mount.controller, mount.lun, mount.path, err)
			}
			mm.untrackMount(mount)
			return nil
		}
	}
	// No mount found for this controller/lun - this is okay
	return nil
}

func (mm *MountManager) Mount(ctx context.Context, controller, lun uint, c *MountConfig) (_ string, err error) {
	// Normalize the mount config for comparison.
	// Config equality relies on the options slices being compared element-wise. Sort the options
	// slice first so that two slices with different ordering compare as equal. We assume that
	// order will never matter for mount options.
	sort.Strings(c.Options)

	mount, existed := mm.trackMount(controller, lun, c)
	if existed {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-mount.waitCh:
			if mount.waitErr != nil {
				return "", mount.waitErr
			}
		}
		return mount.path, nil
	}

	defer func() {
		if err != nil {
			mm.m.Lock()
			mm.untrackMount(mount)
			mm.m.Unlock()
		}

		mount.waitErr = err
		close(mount.waitCh)
	}()

	if err := mm.mounter.mount(ctx, controller, lun, mount.path, c); err != nil {
		return "", fmt.Errorf("mount scsi controller %d lun %d at %s: %w", controller, lun, mount.path, err)
	}
	return mount.path, nil
}

func (mm *MountManager) Unmount(ctx context.Context, path string) (bool, error) {
	mm.m.Lock()
	defer mm.m.Unlock()

	var mount *mount
	for _, mount = range mm.mounts {
		if mount != nil && mount.path == path {
			break
		}
	}

	mount.refCount--
	if mount.refCount > 0 {
		return false, nil
	}

	if err := mm.mounter.unmount(ctx, mount.controller, mount.lun, mount.path, mount.config); err != nil {
		return false, fmt.Errorf("unmount scsi controller %d lun %d at path %s: %w", mount.controller, mount.lun, mount.path, err)
	}
	mm.untrackMount(mount)

	return true, nil
}

func (mm *MountManager) trackMount(controller, lun uint, c *MountConfig) (*mount, bool) {
	mm.m.Lock()
	defer mm.m.Unlock()

	var freeIndex int = -1
	for i, mount := range mm.mounts {
		if mount == nil {
			if freeIndex == -1 {
				freeIndex = i
			}
		} else if controller == mount.controller &&
			lun == mount.lun &&
			reflect.DeepEqual(c, mount.config) {

			mount.refCount++
			return mount, true
		}
	}

	// New mount.
	mount := &mount{
		controller: controller,
		lun:        lun,
		config:     c,
		refCount:   1,
		waitCh:     make(chan struct{}),
	}
	if freeIndex == -1 {
		mount.index = len(mm.mounts)
		mm.mounts = append(mm.mounts, mount)
	} else {
		mount.index = freeIndex
		mm.mounts[freeIndex] = mount
	}
	// Use the mount index to produce a unique guest path.
	mount.path = fmt.Sprintf(mm.mountFmt, mount.index)
	return mount, false
}

// Caller must be holding mm.m.
func (mm *MountManager) untrackMount(mount *mount) {
	mm.mounts[mount.index] = nil
}

func (mm *MountManager) GetMounts() []*state.Mount {
	mm.m.Lock()
	defer mm.m.Unlock()

	var mounts []*state.Mount
	for _, m := range mm.mounts {
		if m == nil {
			continue // Skip unmounted entries
		}
		mounts = append(mounts, &state.Mount{
			Path:       m.path,
			Index:      uint32(m.index),
			Controller: uint32(m.controller),
			Lun:        uint32(m.lun),
			RefCount:   uint32(m.refCount),
			Config: &state.MountConfig{
				Partition:        m.config.Partition,
				ReadOnly:         m.config.ReadOnly,
				Encrypted:        m.config.Encrypted,
				Options:          m.config.Options,
				EnsureFilesystem: m.config.EnsureFileystem,
				Filesystem:       m.config.Filesystem,
			},
		})
	}
	return mounts
}

func (mm *MountManager) HydrateMounts(mounts []*state.Mount) {
	mm.m.Lock()
	defer mm.m.Unlock()

	for _, m := range mounts {
		if m == nil {
			continue
		}

		// Reconstruct internal Mount
		newMount := &mount{
			path:       m.Path,
			index:      int(m.Index),
			controller: uint(m.Controller),
			lun:        uint(m.Lun),
			refCount:   uint(m.RefCount),
			waitCh:     make(chan struct{}),
			config: &MountConfig{
				Partition:       m.Config.Partition,
				ReadOnly:        m.Config.ReadOnly,
				Encrypted:       m.Config.Encrypted,
				Options:         m.Config.Options,
				EnsureFileystem: m.Config.EnsureFilesystem,
				Filesystem:      m.Config.Filesystem,
			},
		}

		// Mark as ready (no pending Mount operation)
		close(newMount.waitCh)

		// Ensure slice is large enough
		if newMount.index >= len(mm.mounts) {
			newMounts := make([]*mount, newMount.index+1)
			copy(newMounts, mm.mounts)
			mm.mounts = newMounts
		}

		mm.mounts[newMount.index] = newMount
	}
}
