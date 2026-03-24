//go:build windows && !wcow

package mount

import (
	"context"
	"fmt"

	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/logfields"
	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
	"github.com/Microsoft/hcsshim/internal/vm/vmutils"

	"github.com/sirupsen/logrus"
)

// plan9MountFmt is the format string for auto-generated guest paths when
// the caller does not provide one explicitly.
const plan9MountFmt = "/run/mounts/plan9/m%d"

// ResolvePlan9GuestPath returns the stable guest path for the Plan9 share
// identified by shareName. If no entry exists yet, ResolvePlan9GuestPath
// pre-allocates one and returns the generated path.
func (m *Manager) ResolvePlan9GuestPath(shareName string, config Plan9MountConfig) string {
	mount := m.getOrCreatePlan9Entry(shareName, &config)
	return mount.guestPath
}

// MountPlan9 mounts a Plan9 share inside the LCOW guest and returns the resolved guest path.
// If the share is already mounted at the requested path with a matching config, the
// existing mount is returned without issuing a duplicate mount request.
func (m *Manager) MountPlan9(ctx context.Context, shareName string, config Plan9MountConfig) (_ string, err error) {

	// Add share name to logging context.
	ctx, _ = log.WithContext(ctx, logrus.WithField("shareName", shareName))

	log.G(ctx).WithFields(logrus.Fields{
		logfields.Options: config,
	}).Debug("Mounting Plan9 share")

	// Track the requested plan9 mount operation.
	mount := m.getOrCreatePlan9Entry(shareName, &config)

	// Add resolved guest path to logging context.
	ctx, _ = log.WithContext(ctx, logrus.WithField(logfields.UVMPath, mount.guestPath))

	// Acquire the entry lock to check the state and potentially drive the mount operation.
	mount.mu.Lock()
	defer mount.mu.Unlock()

	switch mount.state {
	case mountMounted:
		// ==============================================================================
		// Found an existing mount.
		// ==============================================================================

		// Validate it matches the requested share and config.
		if mount.shareName != shareName || mount.config.ReadOnly != config.ReadOnly {
			return "", fmt.Errorf(
				"guest path %q is already mounted for share %q (readOnly=%v), "+
					"cannot reuse for share %q (readOnly=%v)",
				config.GuestPath, mount.shareName, mount.config.ReadOnly,
				shareName, config.ReadOnly)
		}

		mount.refCount++

		log.G(ctx).Debug("reusing existing plan9 guest mount")
		return mount.guestPath, nil

	case mountPending:
		// ==============================================================================
		// New mount - We own this entry.
		// Other goroutines requesting the same path are blocked on mount.mu
		// and will see the final state once we release it.
		// ==============================================================================
		log.G(ctx).Tracef("performing guest operation to mount the share")

		if err := m.linuxGuestPlan9.AddLCOWMappedDirectory(ctx,
			guestresource.LCOWMappedDirectory{
				MountPath: config.GuestPath,
				ShareName: shareName,
				Port:      vmutils.Plan9Port,
				ReadOnly:  config.ReadOnly,
			}); err != nil {

			// Move the state to Invalid so that other goroutines waiting on
			// the mount see the real failure reason via stateErr.
			mount.state = mountInvalid
			mount.stateErr = err

			// Delete from the map. Any callers waiting on this mount
			// will see the invalid state and receive the original error.
			m.globalMu.Lock()
			delete(m.plan9Mounts, mount.guestPath)
			m.globalMu.Unlock()

			return "", fmt.Errorf("mount plan9 share %q in guest at %q: add LCOW mapped directory: %w",
				shareName, config.GuestPath, err)
		}

		// Mark the mount as mounted.
		mount.state = mountMounted
		mount.refCount++

		log.G(ctx).Debug("plan9 share mounted in guest")
		return mount.guestPath, nil

	case mountInvalid:
		// ==============================================================================
		// Found a mount which failed during guest operation.
		// ==============================================================================

		return "", fmt.Errorf("previous mount attempt at %q failed: %w", mount.guestPath, mount.stateErr)

	default:
		// Unlikely state that should never be observed here.
		return "", fmt.Errorf("plan9 guest mount at %q in unexpected state %s", mount.guestPath, mount.state)
	}
}

// getOrCreatePlan9Entry looks up the global Plan9 mount map for an existing entry
// at the requested guest path. If found it is returned as-is. If not found, a new
// Pending entry is inserted and returned. Map access is serialised under globalMu.
func (m *Manager) getOrCreatePlan9Entry(shareName string, config *Plan9MountConfig) *plan9Mount {
	m.globalMu.Lock()
	defer m.globalMu.Unlock()

	// If the requested path exists, return the same.
	if config.GuestPath != "" {
		if mount, ok := m.plan9Mounts[config.GuestPath]; ok {
			return mount
		}
	}

	// Auto-generate a unique path under the global lock so concurrent callers
	// can never receive the same index.
	if config.GuestPath == "" {
		config.GuestPath = fmt.Sprintf(plan9MountFmt, m.nextPlan9MountIdx)
		m.nextPlan9MountIdx++
	}

	// Insert a new mount entry in Pending state.
	mount := &plan9Mount{
		guestPath:  config.GuestPath,
		shareName:  shareName,
		config:     config,
		refTracker: refTracker{state: mountPending},
	}
	m.plan9Mounts[config.GuestPath] = mount

	return mount
}

// UnmountPlan9 releases a previously mounted Plan9 guest path.
// The GCS unmount request is sent only when the last reference is released.
func (m *Manager) UnmountPlan9(ctx context.Context, guestPath string) error {

	ctx, _ = log.WithContext(ctx, logrus.WithField(logfields.UVMPath, guestPath))
	log.G(ctx).Debug("Unmounting Plan9 share from guest")

	// Under global lock, find the mount.
	m.globalMu.Lock()
	mount, ok := m.plan9Mounts[guestPath]
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
		if err := m.linuxGuestPlan9.RemoveLCOWMappedDirectory(ctx, guestresource.LCOWMappedDirectory{
			MountPath: mount.guestPath,
			ShareName: mount.shareName,
			Port:      vmutils.Plan9Port,
			ReadOnly:  mount.config.ReadOnly,
		}); err != nil {
			return fmt.Errorf("unmount plan9 guest path %q: remove LCOW mapped directory: %w", mount.guestPath, err)
		}
		mount.state = mountUnmounted
	}

	// Cleanup from the map.
	m.globalMu.Lock()
	delete(m.plan9Mounts, mount.guestPath)
	m.globalMu.Unlock()

	log.G(ctx).Debug("plan9 share unmounted from guest")
	return nil
}
