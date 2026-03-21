//go:build windows

package mount

import (
	"context"
	"fmt"
	"reflect"
	"sort"

	"github.com/Microsoft/hcsshim/internal/log"
)

func (m *Manager) Mount(
	ctx context.Context,
	controller, lun uint,
	mountCfg MountConfig,
) (_ string, err error) {
	// Get an existing mount if the path is already live in the guest, or
	// perform a fresh mount otherwise.
	gm, err := m.getOrMount(ctx, controller, lun, &mountCfg)
	if err != nil {
		return "", err
	}

	return gm.guestPath, nil
}

// getOrMount looks up the global mount index for an existing live mount
// at the requested guest path.  If found and the config matches, it increments
// the refCount and returns the existing guestMount.  If the path is new, it
// resolves the guest path, and calls the OS-specific mountInGuest.
func (m *Manager) getOrMount(ctx context.Context, controller, lun uint, mountCfg *MountConfig) (*guestMount, error) {
	// Normalize options early so all downstream comparisons are order-independent.
	sort.Strings(mountCfg.Options)

	// m.mounts is the global authority keyed by resolved guest path, so a
	// mount created by one caller is visible here when another caller asks for
	// the same path.
	if mountCfg.GuestPath != "" {
		if gm, ok := m.mounts[mountCfg.GuestPath]; ok {
			// Only reuse mounts that are still in a usable state.
			if gm.state != mountMounted {
				return nil, fmt.Errorf(
					"guest mount at %q is in state %s and cannot be reused",
					mountCfg.GuestPath, gm.state)
			}

			// Reuse only if the existing mount matches the requested slot and config exactly.
			if gm.controller != controller ||
				gm.lun != lun ||
				!reflect.DeepEqual(mountCfg, gm.config) {

				return nil, fmt.Errorf(
					"guest path %q is already mounted at controller=%d lun=%d with config %+v",
					mountCfg.GuestPath, gm.controller, gm.lun, gm.config)
			}

			gm.refCount++
			log.G(ctx).WithField("guestPath", mountCfg.GuestPath).Debug("reusing existing guest mount")
			return gm, nil
		}
	}

	// New mount: resolve the guest path, then perform the guest-specific mount.
	if mountCfg.GuestPath == "" {
		// Use a monotonically increasing index to produce a stable, unique
		// guest path that is never reused after a mount is released.
		mountCfg.GuestPath = fmt.Sprintf(mountFmt, m.nextMountIdx)
		m.nextMountIdx++
	}

	if err := m.mountInGuest(ctx, controller, lun, mountCfg); err != nil {
		return nil, fmt.Errorf("mount SCSI disk at controller=%d lun=%d in guest: %w",
			controller, lun, err)
	}

	gm := &guestMount{
		guestPath:  mountCfg.GuestPath,
		controller: controller,
		lun:        lun,
		config:     mountCfg,
		refCount:   1,
		state:      mountMounted,
	}
	m.mounts[mountCfg.GuestPath] = gm

	log.G(ctx).WithField("guestPath", mountCfg.GuestPath).Debug("SCSI disk mounted in guest")
	return gm, nil
}

func (m *Manager) Unmount(
	ctx context.Context,
	controller, lun uint,
	guestPath string,
) error {
	gm, ok := m.mounts[guestPath]
	if !ok {
		return fmt.Errorf("no guest mount at path %q", guestPath)
	}

	if gm.controller != controller || gm.lun != lun {
		return fmt.Errorf("guest mount at %q is at controller=%d lun=%d, not controller=%d lun=%d",
			guestPath, gm.controller, gm.lun, controller, lun)
	}

	return m.releaseGuestMount(ctx, gm)
}

func (m *Manager) releaseGuestMount(ctx context.Context, gm *guestMount) error {
	if gm.refCount > 0 {
		gm.refCount--
	}
	if gm.refCount > 0 {
		// Other callers still hold a reference to this mount; leave it in place.
		return nil
	}

	// refCount is zero.  Attempt to unmount only if the state allows it.
	if gm.state == mountMounted {
		if err := m.unmountFromGuest(ctx, gm.controller, gm.lun, gm); err != nil {
			// Forward-only: do NOT restore refCount.  State stays at current
			// position so a retry knows the unmount was never done.
			return fmt.Errorf("unmount guest path %q: %w", gm.guestPath, err)
		}
		gm.state = mountUnmounted
	}

	delete(m.mounts, gm.guestPath)
	return nil
}
