//go:build windows

package mount

import (
	"context"
	"fmt"
	"reflect"
	"sort"

	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/logfields"
	"github.com/sirupsen/logrus"
)

// ResolveSCSIGuestPath returns the stable guest path for the SCSI disk at the
// given controller and LUN. If no entry exists yet, ResolveSCSIGuestPath
// pre-allocates one and returns the generated path.
func (m *Manager) ResolveSCSIGuestPath(controller, lun uint, mountCfg SCSIMountConfig) string {
	// Normalize options so concurrent callers that independently resolve and
	// then mount observe identical configs and coalesce onto the same entry.
	sort.Strings(mountCfg.Options)
	mount := m.getOrCreateSCSIEntry(controller, lun, &mountCfg)
	return mount.guestPath
}

// MountSCSI mounts a SCSI disk (identified by controller + LUN) inside the
// guest. If the guest path is not specified, we generate one.
// Returns the resolved guest path.
func (m *Manager) MountSCSI(
	ctx context.Context,
	controller uint,
	lun uint,
	mountCfg SCSIMountConfig,
) (_ string, err error) {

	log.G(ctx).WithFields(logrus.Fields{
		logfields.Controller: controller,
		logfields.LUN:        lun,
		logfields.Options:    mountCfg,
	}).Debug("Mounting SCSI disk inside the guest")

	// Normalize options early so all downstream comparisons are order-independent.
	sort.Strings(mountCfg.Options)

	// Track the SCSI mount operation.
	mount := m.getOrCreateSCSIEntry(controller, lun, &mountCfg)

	ctx, _ = log.WithContext(ctx, logrus.WithField(logfields.UVMPath, mount.guestPath))
	log.G(ctx).WithFields(logrus.Fields{
		logfields.Controller: controller,
		logfields.LUN:        lun,
	}).Debug("checking the status of resolved guest path")

	// Acquire the entry lock to check the state and potentially drive the mount operation.
	mount.mu.Lock()
	defer mount.mu.Unlock()

	switch mount.state {
	case mountMounted:
		// ==============================================================================
		// Found an existing mount.
		// ==============================================================================

		// Validate it matches the requested disk and config.
		if mount.controller != controller || mount.lun != lun || !reflect.DeepEqual(&mountCfg, mount.config) {
			return "", fmt.Errorf(
				"guest path %q is already mounted for controller=%d lun=%d with a different config",
				mountCfg.GuestPath, mount.controller, mount.lun)
		}

		mount.refCount++

		log.G(ctx).Debug("reusing existing SCSI guest mount")
		return mount.guestPath, nil

	case mountPending:
		// ==============================================================================
		// New mount - We own this entry.
		// Other goroutines requesting the same path are blocked on mount.mu
		// and will see the final state once we release it.
		// ==============================================================================
		log.G(ctx).Tracef("performing guest operation to mount the disk")

		if err = m.mountInGuest(ctx, controller, lun, &mountCfg); err != nil {
			// Move the state to Invalid so that other goroutines waiting on
			// the mount see the real failure reason via stateErr.
			mount.state = mountInvalid
			mount.stateErr = err

			// Delete from the map. Any callers waiting on this mount
			// will see the invalid state and receive the original error.
			m.globalMu.Lock()
			delete(m.scsiMounts, mount.guestPath)
			m.globalMu.Unlock()

			return "", fmt.Errorf("mount SCSI disk for controller=%d lun=%d in guest: %w",
				controller, lun, err)
		}

		// Mark the mount as mounted.
		mount.state = mountMounted
		mount.refCount++

		log.G(ctx).Debug("SCSI disk mounted in guest")
		return mount.guestPath, nil

	case mountInvalid:
		// ==============================================================================
		// Found a mount which failed during guest operation.
		// ==============================================================================

		return "", fmt.Errorf("previous mount attempt at %q failed: %w", mount.guestPath, mount.stateErr)

	default:
		// Unlikely state that should never be observed here.
		return "", fmt.Errorf("SCSI guest mount at %q in unexpected state %s", mount.guestPath, mount.state)
	}
}

// getOrCreateSCSIEntry looks up the global SCSI mount map for an existing entry
// at the requested guest path. If found it is returned as-is. If not found, a new
// Pending entry is inserted and returned. All map access is serialised under globalMu.
func (m *Manager) getOrCreateSCSIEntry(controller, lun uint, mountCfg *SCSIMountConfig) *scsiMount {
	m.globalMu.Lock()
	defer m.globalMu.Unlock()

	// If the requested path exists, return the same.
	if mountCfg.GuestPath != "" {
		if mount, ok := m.scsiMounts[mountCfg.GuestPath]; ok {
			return mount
		}
	}

	// Auto-generate a unique path under the global lock so concurrent callers
	// can never receive the same index.
	if mountCfg.GuestPath == "" {
		mountCfg.GuestPath = fmt.Sprintf(mountFmt, m.nextSCSIMountIdx)
		m.nextSCSIMountIdx++
	}

	// Insert a new mount entry in Pending state.
	mount := &scsiMount{
		guestPath:  mountCfg.GuestPath,
		controller: controller,
		lun:        lun,
		config:     mountCfg,
		refTracker: refTracker{state: mountPending},
	}
	m.scsiMounts[mountCfg.GuestPath] = mount
	return mount
}

// UnmountSCSI releases a previously mounted SCSI guest path.
// The GCS unmount request is sent only when the last reference is released.
func (m *Manager) UnmountSCSI(ctx context.Context, guestPath string) error {

	ctx, _ = log.WithContext(ctx, logrus.WithField(logfields.UVMPath, guestPath))
	log.G(ctx).Debug("Unmounting SCSI disk from guest")

	m.globalMu.Lock()
	mount, ok := m.scsiMounts[guestPath]
	m.globalMu.Unlock()

	// If there is no mount, then there is nothing to unmount.
	if !ok {
		return nil
	}

	mount.mu.Lock()
	defer mount.mu.Unlock()

	if mount.refCount > 1 {
		mount.refCount--
		// Other callers still hold a reference to this mount.
		log.G(ctx).Debug("mount still in use by other callers, not unmounting from guest")
		return nil
	}

	// If the mount failed (guest operation never succeeded), but we got the
	// entry just prior to removal from map, then state would be invalid.
	if mount.state == mountInvalid {
		// Mount never succeeded; nothing to undo.
		return nil
	}

	// Drive the unmount operation.
	if mount.state == mountMounted {
		if err := m.unmountFromGuest(ctx, mount.controller, mount.lun, mount); err != nil {
			return fmt.Errorf("unmount SCSI guest path %q: %w", mount.guestPath, err)
		}
		mount.state = mountUnmounted
	}

	// Cleanup from the map.
	m.globalMu.Lock()
	delete(m.scsiMounts, mount.guestPath)
	m.globalMu.Unlock()

	log.G(ctx).Debug("SCSI disk unmounted from guest")
	return nil
}
