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
	"github.com/Microsoft/hcsshim/internal/vm/guestmanager"
	"github.com/Microsoft/hcsshim/internal/vm/vmmanager"

	"github.com/sirupsen/logrus"
)

// Manager implements [Controller] and manages SCSI disk attachment across
// one or more controllers on a Hyper-V VM.
type Manager struct {
	// mu guards attachments and all mutable fields of every [vmAttachment] in the map.
	mu sync.Mutex

	// numControllers is the number of SCSI controllers available on the VM.
	// It bounds the (controller, lun) search space when allocating a free slot.
	numControllers int

	// attachments tracks every disk currently being attached or already attached
	// to the VM. Key = (controller, lun) hardware address.
	// Access must be guarded by mu.
	attachments map[VMSlot]*vmAttachment

	// vmScsiManager is the host-side SCSI manager used to add and remove disks from the VM.
	vmScsiManager vmmanager.SCSIManager

	// linuxGuestMgr is used to perform the guest-side unplug on LCOW prior to detach.
	linuxGuestMgr guestmanager.LCOWScsiManager
}

var _ Controller = (*Manager)(nil)

// New creates a new [Manager] instance conforming to [Controller] interface.
// ReservedSlots are never allocated to new disks.
func New(
	vmScsiManager vmmanager.SCSIManager,
	linuxGuest guestmanager.LCOWScsiManager,
	numControllers int,
	reservedSlots []VMSlot,
) *Manager {
	m := &Manager{
		numControllers: numControllers,
		attachments:    make(map[VMSlot]*vmAttachment, len(reservedSlots)),
		vmScsiManager:  vmScsiManager,
		linuxGuestMgr:  linuxGuest,
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
	ctx, _ = log.WithContext(ctx, logrus.WithField(logfields.Operation, "AttachDiskToVM"))

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
// It calls trackAttachment to either reuse an in-flight attachment or
// claim a new slot, then drives the HCS add-disk call.
func (m *Manager) attachDiskToVM(ctx context.Context, config *diskConfig) (VMSlot, error) {
	// Track the attachment and get the slot to attach to.
	att, existed, err := m.trackAttachment(ctx, config)
	if err != nil {
		return VMSlot{}, err
	}

	// ==============================================================================
	// Found an existing attachment.
	// ==============================================================================
	if existed {
		// Another goroutine is already attaching (or has attached) the same disk.
		// Wait for it to finish, honoring context cancellation.
		select {
		case <-ctx.Done():
			// Undo the refCount bump from trackAttachment so the
			// attachment can eventually reach zero and be torn down.
			m.mu.Lock()
			att.refCount--
			m.mu.Unlock()
			return VMSlot{}, ctx.Err()
		case <-att.waitCh:
			if att.waitErr != nil {
				// The original attach failed.
				// The attachment will be removed from the map.
				return VMSlot{}, att.waitErr
			}
		}

		log.G(ctx).WithFields(logrus.Fields{
			logfields.Controller: att.controller,
			logfields.LUN:        att.lun,
		}).Debug("reusing existing SCSI VM attachment")

		return VMSlot{Controller: att.controller, LUN: att.lun}, nil
	}

	// ==============================================================================
	// New attachment — we own the slot.
	// ==============================================================================

	// Perform the host-side HCS call to add the disk at the allocated (controller, lun) slot.
	log.G(ctx).WithFields(logrus.Fields{
		logfields.Controller: att.controller,
		logfields.LUN:        att.lun,
	}).Debug("performing AddSCSIDisk call to add disk to VM")

	err = m.vmScsiManager.AddSCSIDisk(ctx, hcsschema.Attachment{
		Path:                      config.hostPath,
		Type_:                     string(config.typ),
		ReadOnly:                  config.readOnly,
		ExtensibleVirtualDiskType: config.evdType,
	}, att.controller, att.lun)

	// Signal completion to any goroutines waiting on the same disk.
	att.waitErr = err
	close(att.waitCh)

	// Clean up on failure.
	if err != nil {
		m.mu.Lock()
		delete(m.attachments, VMSlot{att.controller, att.lun})
		m.mu.Unlock()

		return VMSlot{}, fmt.Errorf("add scsi disk %q to vm at controller=%d lun=%d: %w",
			config.hostPath, att.controller, att.lun, err)
	}

	log.G(ctx).WithFields(logrus.Fields{
		logfields.Controller: att.controller,
		logfields.LUN:        att.lun,
	}).Debug("SCSI disk attached to VM")

	return VMSlot{Controller: att.controller, LUN: att.lun}, nil
}

// trackAttachment either reuses an existing [vmAttachment] for the same disk config,
// incrementing its reference count, or allocates the first free (controller, lun) slot
// and registers a new [vmAttachment] in the internal map.
func (m *Manager) trackAttachment(ctx context.Context, config *diskConfig) (*vmAttachment, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Reuse an existing attachment for the same disk.
	for _, existing := range m.attachments {
		if existing.config != nil && *existing.config == *config {
			existing.refCount++
			return existing, true, nil
		}
	}

	log.G(ctx).Debug("no existing attachment found for disk, allocating new slot")

	// Find the first free (controller, lun) pair.
	for ctrl := uint(0); ctrl < uint(m.numControllers); ctrl++ {
		for lun := uint(0); lun < numLUNsPerController; lun++ {
			key := VMSlot{ctrl, lun}
			// if the slot is occupied, then continue to next slot.
			if _, occupied := m.attachments[key]; occupied {
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
				refCount:   1,
				state:      attachmentAttached,
				waitCh:     make(chan struct{}),
			}
			m.attachments[key] = att
			return att, false, nil
		}
	}

	return nil, false, errors.New("no available scsi slot")
}

// DetachFromVM detaches the disk at slot from the VM, unplugging it from the guest first.
// If the disk is shared with other callers, DetachFromVM returns without removing it
// until the last caller detaches.
func (m *Manager) DetachFromVM(
	ctx context.Context,
	slot VMSlot,
) error {
	ctx, _ = log.WithContext(ctx, logrus.WithFields(logrus.Fields{
		logfields.Operation:  "DetachFromVM",
		logfields.Controller: slot.Controller,
		logfields.LUN:        slot.LUN,
	}))

	log.G(ctx).Debug("Detaching from VM")

	m.mu.Lock()
	defer m.mu.Unlock()

	existing, ok := m.attachments[slot]
	if !ok {
		return fmt.Errorf("no existing attachment found for controller=%d lun=%d", slot.Controller, slot.LUN)
	}

	if existing.state == attachmentReserved {
		return fmt.Errorf("cannot release reserved attachment at controller=%d lun=%d", slot.Controller, slot.LUN)
	}

	if existing.refCount > 0 {
		existing.refCount--
	}
	if existing.refCount > 0 {
		// Other callers still hold a reference to this disk.
		log.G(ctx).Debug("disk still in use by other callers, not detaching from VM")
		return nil
	}

	// Unplug the device from the guest before removing it from the VM.
	// Skip if already unplugged from a previous attempt where RemoveSCSIDisk
	// failed after a successful unplug.
	if existing.state == attachmentAttached {
		if err := m.unplugFromGuest(ctx, slot.Controller, slot.LUN); err != nil {
			return fmt.Errorf("unplug scsi disk at controller=%d lun=%d from guest: %w",
				slot.Controller, slot.LUN, err)
		}
		existing.state = attachmentUnplugged

		log.G(ctx).Debug("disk unplugged from guest")
	}

	if existing.state == attachmentUnplugged {
		if err := m.vmScsiManager.RemoveSCSIDisk(ctx, slot.Controller, slot.LUN); err != nil {
			return fmt.Errorf("remove scsi disk at controller=%d lun=%d from vm: %w",
				slot.Controller, slot.LUN, err)
		}
		existing.state = attachmentDetached
	}

	delete(m.attachments, slot)

	log.G(ctx).WithFields(logrus.Fields{
		logfields.Controller: slot.Controller,
		logfields.LUN:        slot.LUN,
	}).Debug("SCSI disk detached from VM")

	return nil
}

// parseEVDPath splits an EVD host path of the form "evd://<type>/<mountPath>" into
// its EVD provider type and the underlying mount path.
// Returns an error if the path does not conform to this scheme.
func parseEVDPath(hostPath string) (evdType, mountPath string, err error) {
	trimmedPath := strings.TrimPrefix(hostPath, "evd://")
	separatorIndex := strings.Index(trimmedPath, "/")
	if separatorIndex <= 0 {
		return "", "", fmt.Errorf("invalid extensible vhd path: %q", hostPath)
	}
	return trimmedPath[:separatorIndex], trimmedPath[separatorIndex+1:], nil
}
