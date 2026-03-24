//go:build windows

package scsi

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/logfields"
	"github.com/Microsoft/hcsshim/internal/wclayer"

	"github.com/sirupsen/logrus"
)

// Manager implements the methods to manage SCSI disk attachment across
// one or more controllers on a Hyper-V VM.
type Manager struct {
	// globalMu protects the attachments map and serializes slot allocation across concurrent callers.
	globalMu sync.Mutex

	// vmID is the ID for the HCS compute system to which we are attaching disks.
	vmID string

	// numControllers is the number of SCSI controllers available on the VM.
	// It bounds the (controller, lun) search space when allocating a free slot.
	numControllers int

	// attachments tracks every disk currently being attached or already attached
	// to the VM. Keyed by VMSlot{Controller, LUN}.
	// An absent entry means the slot is free. Access must be guarded by globalMu.
	attachments map[VMSlot]*vmAttachment

	// vmSCSI is the host-side SCSI manager used to add and remove disks from the VM.
	vmSCSI vmSCSI

	// linuxGuestSCSI is used to perform the guest-side unplug on LCOW prior to detach.
	linuxGuestSCSI linuxGuestSCSI
}

// New creates a new [Manager] instance for managing disk attachments.
// ReservedSlots are never allocated to new disks.
func New(
	vmID string,
	vmScsi vmSCSI,
	linuxGuestScsi linuxGuestSCSI,
	numControllers int,
	reservedSlots []VMSlot,
) *Manager {
	m := &Manager{
		vmID:           vmID,
		numControllers: numControllers,
		attachments:    make(map[VMSlot]*vmAttachment),
		vmSCSI:         vmScsi,
		linuxGuestSCSI: linuxGuestScsi,
	}

	// Pre-populate attachments with reserved slots so they are never allocated to new disks.
	for _, s := range reservedSlots {
		m.attachments[s] = &vmAttachment{
			controller: s.Controller,
			lun:        s.LUN,
			refCount:   1,
			state:      attachmentReserved,
		}
	}

	return m
}

// AttachDiskToVM attaches the disk at hostPath to the VM and returns the allocated [VMSlot].
// If the same disk is already in flight or attached, AttachDiskToVM blocks until the
// original operation completes and then returns the shared slot.
func (m *Manager) AttachDiskToVM(
	ctx context.Context,
	hostPath string,
	diskType DiskType,
	readOnly bool,
) (VMSlot, error) {

	log.G(ctx).WithFields(logrus.Fields{
		logfields.HostPath: hostPath,
		logfields.DiskType: diskType,
		logfields.ReadOnly: readOnly,
	}).Debug("Attaching disk to VM")

	// Create the disk config for the VM.
	config := &diskConfig{
		hostPath: hostPath,
		readOnly: readOnly,
		typ:      diskType,
	}

	// For Virtual and Physical disks, we need to grant VM access to the VHD.
	if diskType == DiskTypeVirtualDisk || diskType == DiskTypePassThru {
		log.G(ctx).WithField(logfields.HostPath, hostPath).Debug("Granting VM access to disk")

		if err := wclayer.GrantVmAccess(ctx, m.vmID, hostPath); err != nil {
			return VMSlot{}, err
		}
	}

	// Parse EVD-specific fields out of hostPath before forwarding to attachDiskToVM,
	if diskType == DiskTypeExtensibleVirtualDisk {
		evdType, evdMountPath, err := parseEVDPath(hostPath)
		if err != nil {
			return VMSlot{}, err
		}
		config.hostPath = evdMountPath
		config.evdType = evdType
	}

	return m.attachDiskToVM(ctx, config)
}

// attachDiskToVM is the internal implementation of [Manager.AttachDiskToVM].
// It calls [Manager.getOrAllocateSlot] to reuse an existing slot or allocate a new one,
// then drives the HCS add-disk call. On failure the attachment is removed from
// the internal map and the error is returned.
func (m *Manager) attachDiskToVM(ctx context.Context, config *diskConfig) (VMSlot, error) {
	// Track the attachment and get the slot for attachment.
	// The attachment may be Pending, Attached, or Invalid.
	att, err := m.getOrAllocateSlot(ctx, config)
	if err != nil {
		return VMSlot{}, err
	}

	// Acquire the attachment mutex to check the state and potentially drive the attach operation.
	att.mu.Lock()
	defer att.mu.Unlock()

	ctx, _ = log.WithContext(ctx, logrus.WithFields(logrus.Fields{
		logfields.Controller: att.controller,
		logfields.LUN:        att.lun,
	}))

	log.G(ctx).Debug("received attachment for disk, checking state")

	switch att.state {
	case attachmentAttached:
		// ==============================================================================
		// Found an existing attachment.
		// ==============================================================================
		att.refCount++
		slot := VMSlot{Controller: att.controller, LUN: att.lun}

		log.G(ctx).Debug("disk already attached to VM, reusing existing slot")

		return slot, nil
	case attachmentPending:
		// ==============================================================================
		// New attachment — we own the slot.
		// Other callers requesting this attachment will block on
		// att.mu until we transition the state out of Pending.
		// ==============================================================================

		log.G(ctx).Debug("performing AddSCSIDisk call to add disk to VM")

		// Perform the host-side HCS call to add the disk at the allocated (controller, lun) slot.
		if err = m.vmSCSI.AddSCSIDisk(ctx, hcsschema.Attachment{
			Path:                      config.hostPath,
			Type_:                     string(config.typ),
			ReadOnly:                  config.readOnly,
			ExtensibleVirtualDiskType: config.evdType,
		}, att.controller, att.lun); err != nil {

			// Move the state to Invalid so that other goroutines waiting on
			// the same attachment see the real failure reason via stateErr.
			att.state = attachmentInvalid
			att.stateErr = err

			// Delete from the map. Any callers waiting on this attachment
			// will see the invalid state and receive the original error.
			m.globalMu.Lock()
			delete(m.attachments, VMSlot{Controller: att.controller, LUN: att.lun})
			m.globalMu.Unlock()

			return VMSlot{}, fmt.Errorf("add scsi disk %q to vm at controller=%d lun=%d: %w",
				config.hostPath, att.controller, att.lun, err)
		}

		// Mark the attachment as attached so that future callers can reuse it.
		att.state = attachmentAttached
		att.refCount++

		log.G(ctx).Debug("SCSI disk attached to VM")

		return VMSlot{Controller: att.controller, LUN: att.lun}, nil
	case attachmentInvalid:
		// ==============================================================================
		// Found an attachment which failed during HCS operation.
		// ==============================================================================

		// Return the original error. The map entry has already been removed
		// by the goroutine that drove the failed attach.
		return VMSlot{}, fmt.Errorf("previous attempt to attach disk to VM at controller=%d lun=%d failed: %w",
			att.controller, att.lun, att.stateErr)
	default:
		// Unlikely state that should never be observed here.
		return VMSlot{}, fmt.Errorf("disk in unexpected state %s during attach", att.state)
	}
}

// getOrAllocateSlot either reuses an existing [vmAttachment] for the same disk config,
// incrementing its reference count, or allocates the first free (controller, lun) slot
// and registers a new [vmAttachment] in the internal map.
func (m *Manager) getOrAllocateSlot(ctx context.Context, config *diskConfig) (*vmAttachment, error) {
	m.globalMu.Lock()
	defer m.globalMu.Unlock()

	// Reuse an existing attachment for the same disk.
	for _, existing := range m.attachments {
		if existing != nil && existing.config != nil && existing.config.hostPath == config.hostPath {
			return existing, nil
		}
	}

	log.G(ctx).Debug("no existing attachment found for disk, allocating new slot")

	// Find the first free (controller, lun) pair.
	for ctrl := range m.numControllers {
		for lun := range numLUNsPerController {
			slot := VMSlot{Controller: uint(ctrl), LUN: uint(lun)}

			// if the slot is occupied, then continue to next slot.
			if _, occupied := m.attachments[slot]; occupied {
				continue
			}

			// Found a slot, return it.
			log.G(ctx).WithFields(logrus.Fields{
				logfields.Controller: ctrl,
				logfields.LUN:        lun,
			}).Debug("allocating new attachment")

			att := &vmAttachment{
				config:     config,
				controller: uint(ctrl),
				lun:        uint(lun),
				// Refcount is 0 here since the attachment has not been claimed yet.
				refCount: 0,
				state:    attachmentPending,
			}
			m.attachments[slot] = att
			return att, nil
		}
	}

	return nil, errors.New("no available scsi slot")
}

// DetachFromVM detaches the disk at slot from the VM, unplugging it from the guest first.
// If the disk is shared with other callers, DetachFromVM returns without removing it
// until the last caller detaches.
func (m *Manager) DetachFromVM(
	ctx context.Context,
	slot VMSlot,
) (err error) {

	ctx, _ = log.WithContext(ctx, logrus.WithFields(logrus.Fields{
		logfields.Controller: slot.Controller,
		logfields.LUN:        slot.LUN,
	}))

	log.G(ctx).Debug("Detaching from VM")

	// Under global lock, find the attachment.
	m.globalMu.Lock()
	// Get the attachment for this slot and unlock global lock.
	att := m.attachments[slot]
	m.globalMu.Unlock()

	// If there is no attachment, then the slot is already free and there is nothing to detach.
	if att == nil {
		return nil
	}

	if att.state == attachmentReserved {
		return fmt.Errorf("cannot release reserved attachment at controller=%d lun=%d", slot.Controller, slot.LUN)
	}

	att.mu.Lock()
	defer att.mu.Unlock()

	if att.refCount > 1 {
		att.refCount--
		// Other callers still hold a reference to this disk.
		log.G(ctx).Debug("disk still in use by other callers, not detaching from VM")
		return
	}

	// If the disk attach failed (AddSCSIDisk never succeeded), but we got the
	// entry just prior to removal from map, then state would be invalid.
	if att.state == attachmentInvalid {
		return nil
	}

	// Unplug the device from the guest before removing it from the VM.
	// Skip if already unplugged from a previous attempt where RemoveSCSIDisk
	// failed after a successful unplug.
	if att.state == attachmentAttached {
		if err := m.unplugFromGuest(ctx, slot.Controller, slot.LUN); err != nil {
			return fmt.Errorf("unplug scsi disk at controller=%d lun=%d from guest: %w",
				slot.Controller, slot.LUN, err)
		}
		att.state = attachmentUnplugged

		log.G(ctx).Debug("disk unplugged from guest")
	}

	if att.state == attachmentUnplugged {
		if err := m.vmSCSI.RemoveSCSIDisk(ctx, slot.Controller, slot.LUN); err != nil {
			return fmt.Errorf("remove scsi disk at controller=%d lun=%d from vm: %w",
				slot.Controller, slot.LUN, err)
		}
		att.state = attachmentDetached
	}

	// Cleanup from the map.
	m.globalMu.Lock()
	delete(m.attachments, slot)
	m.globalMu.Unlock()

	log.G(ctx).Debug("SCSI disk detached from VM")

	return nil
}

// parseEVDPath splits an EVD host path of the form "evd://<type>/<mountPath>" into
// its EVD provider type and the underlying mount path.
// Returns an error if the path does not conform to this scheme.
func parseEVDPath(hostPath string) (evdType, mountPath string, err error) {
	if !strings.HasPrefix(hostPath, "evd://") {
		return "", "", fmt.Errorf("invalid extensible vhd path: %q", hostPath)
	}

	trimmedPath := strings.TrimPrefix(hostPath, "evd://")
	separatorIndex := strings.Index(trimmedPath, "/")
	if separatorIndex <= 0 {
		return "", "", fmt.Errorf("invalid extensible vhd path: %q", hostPath)
	}
	return trimmedPath[:separatorIndex], trimmedPath[separatorIndex+1:], nil
}
