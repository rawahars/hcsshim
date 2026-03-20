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

	"github.com/sirupsen/logrus"
)

// Manager implements [Controller] and manages SCSI disk attachment across
// one or more controllers on a Hyper-V VM.
type Manager struct {
	// globalMu protects the attachments map and serializes slot allocation across concurrent callers.
	globalMu sync.Mutex

	// numControllers is the number of SCSI controllers available on the VM.
	// It bounds the (controller, lun) search space when allocating a free slot.
	numControllers int

	// attachments tracks every disk currently being attached or already attached
	// to the VM. Indexed as attachments[controller][lun].
	// A nil entry means the slot is free. Access must be guarded by globalMu.
	attachments [][]*vmAttachment

	// vmSCSI is the host-side SCSI manager used to add and remove disks from the VM.
	vmSCSI vmSCSI

	// linuxGuestSCSI is used to perform the guest-side unplug on LCOW prior to detach.
	linuxGuestSCSI linuxGuestSCSI
}

var _ Controller = (*Manager)(nil)

// New creates a new [Manager] instance conforming to [Controller] interface.
// ReservedSlots are never allocated to new disks.
func New(
	vmScsi vmSCSI,
	linuxGuestScsi linuxGuestSCSI,
	numControllers int,
	reservedSlots []VMSlot,
) *Manager {
	attachments := make([][]*vmAttachment, numControllers)
	for i := range attachments {
		attachments[i] = make([]*vmAttachment, numLUNsPerController)
	}

	m := &Manager{
		numControllers: numControllers,
		attachments:    attachments,
		vmSCSI:         vmScsi,
		linuxGuestSCSI: linuxGuestScsi,
	}

	// Pre-populate attachments with reserved slots so they are never allocated to new disks.
	for _, s := range reservedSlots {
		m.attachments[s.Controller][s.LUN] = &vmAttachment{
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
// It calls [Manager.trackAttachment] to reuse an existing slot or allocate a new one,
// then drives the HCS add-disk call. On failure the attachment is marked invalid and
// the caller must invoke [Manager.DetachFromVM] to clean up the entry.
func (m *Manager) attachDiskToVM(ctx context.Context, config *diskConfig) (VMSlot, error) {
	// Track the attachment and get the slot for attachment.
	// The attachment may be Pending, Attached, or Invalid.
	m.globalMu.Lock()
	att, err := m.trackAttachment(ctx, config)
	if err != nil {
		m.globalMu.Unlock()
		return VMSlot{}, err
	}

	// Acquire the attachment mutex to check the state and potentially drive the attach operation.
	att.mu.Lock()
	// Release the global lock.
	m.globalMu.Unlock()
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
			// The caller must call DetachFromVM to remove the map entry.
			att.state = attachmentInvalid
			att.stateErr = err

			return VMSlot{Controller: att.controller, LUN: att.lun},
				fmt.Errorf("add scsi disk %q to vm at controller=%d lun=%d: %w",
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

		// Return the original error along with the slot so the caller can
		// call DetachFromVM to clean up the entry.
		return VMSlot{Controller: att.controller, LUN: att.lun},
			fmt.Errorf("previous attempt to attach disk to VM at controller=%d lun=%d failed: %w",
				att.controller, att.lun, att.stateErr)
	default:
		// Unlikely state that should never be observed here.
		return VMSlot{}, fmt.Errorf("disk in unexpected state %s during attach", att.state)
	}
}

// trackAttachment either reuses an existing [vmAttachment] for the same disk config,
// incrementing its reference count, or allocates the first free (controller, lun) slot
// and registers a new [vmAttachment] in the internal map.
func (m *Manager) trackAttachment(ctx context.Context, config *diskConfig) (*vmAttachment, error) {
	// Reuse an existing attachment for the same disk.
	for _, row := range m.attachments {
		for _, existing := range row {
			if existing != nil && existing.config != nil && *existing.config == *config {
				return existing, nil
			}
		}
	}

	log.G(ctx).Debug("no existing attachment found for disk, allocating new slot")

	// Find the first free (controller, lun) pair.
	for ctrl := uint(0); ctrl < uint(m.numControllers); ctrl++ {
		for lun := uint(0); lun < numLUNsPerController; lun++ {
			// if the slot is occupied, then continue to next slot.
			if m.attachments[ctrl][lun] != nil {
				continue
			}

			// Found a slot, return it.
			log.G(ctx).WithFields(logrus.Fields{
				logfields.Controller: ctrl,
				logfields.LUN:        lun,
			}).Debug("allocating new attachment")

			att := &vmAttachment{
				config:     config,
				controller: ctrl,
				lun:        lun,
				// Refcount is 0 here since the attachment has not been claimed yet.
				refCount: 0,
				state:    attachmentPending,
			}
			m.attachments[ctrl][lun] = att
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
) error {
	ctx, _ = log.WithContext(ctx, logrus.WithFields(logrus.Fields{
		logfields.Controller: slot.Controller,
		logfields.LUN:        slot.LUN,
	}))

	log.G(ctx).Debug("Detaching from VM")

	// Under global lock, find the attachment and lock it before releasing
	// globalMu. This prevents a concurrent AttachDiskToVM from observing the
	// attachment and incrementing its refCount between our globalMu.Unlock and
	// att.mu.Lock.
	m.globalMu.Lock()

	// Ensure the slot is valid.
	if slot.Controller >= uint(m.numControllers) || slot.LUN >= numLUNsPerController {
		m.globalMu.Unlock()
		return fmt.Errorf("invalid slot: controller=%d lun=%d", slot.Controller, slot.LUN)
	}

	att := m.attachments[slot.Controller][slot.LUN]
	if att == nil {
		m.globalMu.Unlock()
		return fmt.Errorf("no existing attachment found for controller=%d lun=%d", slot.Controller, slot.LUN)
	}

	if att.state == attachmentReserved {
		m.globalMu.Unlock()
		return fmt.Errorf("cannot release reserved attachment at controller=%d lun=%d", slot.Controller, slot.LUN)
	}

	// Lock the attachment while still holding globalMu to close the race window.
	att.mu.Lock()
	m.globalMu.Unlock()
	defer att.mu.Unlock()

	if att.refCount > 0 {
		att.refCount--
	}
	if att.refCount > 0 {
		// Other callers still hold a reference to this disk.
		log.G(ctx).Debug("disk still in use by other callers, not detaching from VM")
		return nil
	}

	// If the disk attach failed (AddSCSIDisk never succeeded), just remove the map
	// entry — there is nothing to unplug or detach on the host.
	if att.state == attachmentInvalid {
		log.G(ctx).WithError(att.stateErr).Error("previous attach attempt failed, cleaning up invalid attachment")

		m.globalMu.Lock()
		m.attachments[slot.Controller][slot.LUN] = nil
		m.globalMu.Unlock()

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

	// Re-acquire globalMu to safely remove the entry from the map.
	m.globalMu.Lock()
	m.attachments[slot.Controller][slot.LUN] = nil
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
