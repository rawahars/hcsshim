//go:build windows

package scsi

import (
	"context"
	"fmt"

	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/logfields"

	"github.com/sirupsen/logrus"
)

// UnmapFromGuest tears down the mount and attachment associated with mappingID.
func (m *Manager) UnmapFromGuest(
	ctx context.Context,
	mappingID string,
) error {
	ctx, _ = log.WithContext(ctx, logrus.WithField(logfields.MappingID, mappingID))
	log.G(ctx).Debug("unmapping SCSI disk from guest")

	m.mu.Lock()
	defer m.mu.Unlock()

	// Look up the mapping by ID.
	mp, ok := m.mappingMap[mappingID]
	if !ok {
		return fmt.Errorf("mapping %q not found", mappingID)
	}

	att := mp.att
	controller, lun := att.controller, att.lun
	partition := mp.partition
	// Create the attachment identifier.
	slot := VMSlot{Controller: controller, LUN: lun}

	ctx, _ = log.WithContext(ctx, logrus.WithFields(logrus.Fields{
		logfields.Controller: controller,
		logfields.LUN:        lun,
		"partition":          partition,
	}))

	// Reserved attachments must never be torn down.
	if att.state == attachReserved {
		return fmt.Errorf("cannot unmap reserved slot at controller=%d lun=%d", controller, lun)
	}

	// ==============================================================================
	// Mount teardown
	// ==============================================================================

	// Handle the mount for this partition.
	mnt := att.partitions[partition]
	// Mount can be nil if we released the mount in prior failed UnmapFromGuest call.
	if mnt != nil {

		// ==============================================================================
		// Mounted state: decrease refCount and drive unmount if required.
		// ==============================================================================
		if mnt.state == mountMounted {
			if mnt.refCount > 0 {
				mnt.refCount--
			}

			if mnt.refCount > 0 {
				// Mount is still used by other callers.
				// The unmap operation for this mapping is complete.
				log.G(ctx).Debug("mount used by other mappings, unmap complete")

				delete(m.mappingMap, mappingID)
				return nil
			}

			// Drive unmount if this was last reference of the mount.
			if err := m.unmountFromGuest(ctx, controller, lun, mnt); err != nil {
				// If we fail here, restore the ref-count since we are already mounted.
				mnt.refCount++
				return fmt.Errorf("unmount scsi disk from guest at %q: %w", mnt.guestPath, err)
			}

			mnt.state = mountUnmounted
			log.G(ctx).Debug("partition unmounted from guest")
		}

		// ==============================================================================
		// Pending or Unmounted state: release the partition.
		// ==============================================================================
		if mnt.state == mountPending || mnt.state == mountUnmounted {
			delete(att.partitions, partition)
			log.G(ctx).Debug("partition released")
		}
	}

	// ==============================================================================
	// Attachment teardown
	// ==============================================================================

	// Drive the attachment teardown when no partitions remain on this disk.
	if len(att.partitions) == 0 {

		// ==============================================================================
		// Attached or Detaching state: unplug the device from the guest.
		// ==============================================================================
		if att.state == attachAttached || att.state == attachDetaching {
			att.state = attachDetaching

			if err := m.unplugFromGuest(ctx, controller, lun); err != nil {
				return fmt.Errorf("unplug scsi device at controller=%d lun=%d from guest: %w",
					controller, lun, err)
			}

			att.state = attachUnplugged
			log.G(ctx).Debug("SCSI device unplugged from guest")
		}

		// ==============================================================================
		// Unplugged state: remove the disk from the VM's SCSI bus.
		// ==============================================================================
		if att.state == attachUnplugged {
			if err := m.vmSCSI.RemoveSCSIDisk(ctx, controller, lun); err != nil {
				return fmt.Errorf("remove scsi disk at controller=%d lun=%d from vm: %w",
					controller, lun, err)
			}

			att.state = attachDetached
			log.G(ctx).Debug("SCSI disk detached from VM")
		}

		// ==============================================================================
		// Pending or Detached state: release the SCSI slot.
		// ==============================================================================
		if att.state == attachPending || att.state == attachDetached {
			delete(m.attachmentMap, slot)
			log.G(ctx).Debug("SCSI slot released")
		}
	}

	// Remove the mapping entry last so that it remains available for retries
	// if any earlier step fails.
	delete(m.mappingMap, mappingID)

	log.G(ctx).Debug("unmap operation complete")

	return nil
}
