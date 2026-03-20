//go:build windows

package scsi

import (
	"context"
	"errors"
	"fmt"
	"strings"

	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/logfields"
	"github.com/Microsoft/hcsshim/internal/wclayer"

	"github.com/sirupsen/logrus"
)

// MapToGuest attaches a SCSI disk to the VM and mounts the requested partition
// in the guest, returning the guest path. The call is idempotent for the same
// mappingID and supports multiple mappings sharing a single disk or partition.
func (m *Manager) MapToGuest(
	ctx context.Context,
	mappingID string,
	diskConfig DiskConfig,
	mountConfig MountConfig,
) (string, error) {

	log.G(ctx).WithFields(logrus.Fields{
		logfields.MappingID: mappingID,
		logfields.HostPath:  diskConfig.HostPath,
		logfields.DiskType:  diskConfig.Type,
	}).Debug("mapping SCSI disk to guest")

	// Parse EVD-specific fields out of the host path so that the HostPath key
	// used for deduplication is the underlying mount path, not the evd:// URI.
	if diskConfig.Type == DiskTypeExtensibleVirtualDisk {
		evdType, mountPath, parseErr := parseEVDPath(diskConfig.HostPath)
		if parseErr != nil {
			return "", parseErr
		}
		diskConfig.HostPath = mountPath
		diskConfig.EVDType = evdType
	}

	// Hold global lock.
	m.mu.Lock()
	defer m.mu.Unlock()

	// Resolve the attachment, mount, and mapping for this request.
	res, isAlreadyMounted, err := m.resolveMapping(ctx, mappingID, &diskConfig, &mountConfig)
	if err != nil {
		return "", err
	}
	// If this was a duplicate idempotent call for same mapping,
	// we return the mounted guest path.
	if isAlreadyMounted {
		return res.att.partitions[res.partition].guestPath, nil
	}

	att := res.att
	controller, lun := att.controller, att.lun
	partition := res.partition

	ctx, _ = log.WithContext(ctx, logrus.WithFields(logrus.Fields{
		logfields.MappingID:  mappingID,
		logfields.Controller: controller,
		logfields.LUN:        lun,
		"partition":          partition,
	}))

	// Drive the attachment state machine. On error the state stays at
	// [attachPending] so a retry with the same mappingID re-enters this case.
	switch att.state {
	case attachPending:
		// ==============================================================================
		// Pending state: we need to attach the disk to the VM and create a new mount.
		// ==============================================================================

		// Grant VM access for virtual and physical disks before attaching.
		if att.diskConfig.Type == DiskTypeVirtualDisk || att.diskConfig.Type == DiskTypePassThru {
			log.G(ctx).WithField(logfields.HostPath, att.diskConfig.HostPath).Debug("granting VM access to disk")

			if err := wclayer.GrantVmAccess(ctx, m.vmID, att.diskConfig.HostPath); err != nil {
				return "", fmt.Errorf("grant vm access to %q: %w", att.diskConfig.HostPath, err)
			}
		}

		log.G(ctx).Debug("attaching disk to VM SCSI bus")

		// Attach the disk to VM bus.
		if err := m.vmSCSI.AddSCSIDisk(ctx, hcsschema.Attachment{
			Path:                      att.diskConfig.HostPath,
			Type_:                     string(att.diskConfig.Type),
			ReadOnly:                  att.diskConfig.ReadOnly,
			ExtensibleVirtualDiskType: att.diskConfig.EVDType,
		}, controller, lun); err != nil {
			// The attachment and mapping entries remain in the maps in attachPending
			// state so the call is retriable. Caller can retry by calling MapToGuest again with
			// the same mappingID, or call UnmapFromGuest to release the entries.
			return "", fmt.Errorf("add scsi disk %q to vm at controller=%d lun=%d: %w",
				att.diskConfig.HostPath, controller, lun, err)
		}

		// We move to attached state.
		att.state = attachAttached
		log.G(ctx).Debug("SCSI disk attached to VM")

	case attachAttached:
		// ==============================================================================
		// Attached state: Nothing to do. The mount ref-count (mnt.refCount) is
		// incremented below; len(att.partitions) is used by UnmapFromGuest to decide
		// when to detach the disk.
		// ==============================================================================
		log.G(ctx).Debug("disk already attached to VM, skipping attach")

	default:
		// ==============================================================================
		// Other states: we need to attach the disk to the VM and create a new mount.
		// ==============================================================================
		return "", fmt.Errorf("attachment at controller=%d lun=%d in state %s, cannot map",
			controller, lun, att.state)
	}

	// Resolve the mount for the requested partition.
	mnt, ok := att.partitions[partition]
	if !ok {
		return "", fmt.Errorf("no mount for partition %d at controller=%d lun=%d",
			partition, controller, lun)
	}

	// Drive the mount state machine. On error the state is unchanged, so a retry re-enters
	// the same case.
	switch mnt.state {
	// ==============================================================================
	// Pending state: we need to perform guest mount.
	// ==============================================================================
	case mountPending:
		log.G(ctx).Debug("mounting partition in guest")

		// Perform platform specific mount operation.
		if err := m.mountInGuest(ctx, controller, lun, mnt); err != nil {
			return "", fmt.Errorf("mount scsi disk in guest at %q controller=%d lun=%d partition=%d: %w",
				mnt.guestPath, controller, lun, partition, err)
		}

		// Mark the state as mounted and increment the ref-count.
		mnt.state = mountMounted
		mnt.refCount++
		log.G(ctx).WithField(logfields.UVMPath, mnt.guestPath).Debug("partition mounted in guest")

	case mountMounted:
		// ==============================================================================
		// Mounted state: we need to increment ref-count.
		// ==============================================================================
		mnt.refCount++

	default:
		// We can reach here is the mount was unmounted during UnmountFromGuest
		// but then operation failed during attachment unplug.
		return "", fmt.Errorf("mount for partition %d at controller=%d lun=%d in state %s, cannot map",
			partition, controller, lun, mnt.state)
	}

	return mnt.guestPath, nil
}

// resolveMapping resolves a mapping ID to a concrete mapping, creating the underlying
// attachment, mount, and mapping entries as needed.
func (m *Manager) resolveMapping(
	ctx context.Context,
	mappingID string,
	diskConfig *DiskConfig,
	mountConfig *MountConfig,
) (*mapping, bool, error) {
	// Check for a mapping conflict before touching any other maps.
	if existing, ok := m.mappingMap[mappingID]; ok {
		if existing.att.diskConfig.HostPath != diskConfig.HostPath || existing.partition != mountConfig.Partition {

			return nil, false, fmt.Errorf(
				"mapping %q conflicts: existing hostPath=%q partition=%d, requested hostPath=%q partition=%d",
				mappingID, existing.att.diskConfig.HostPath, existing.partition, diskConfig.HostPath, mountConfig.Partition)
		}
	}

	// Get or create the attachment for this disk.
	att, err := m.getOrCreateAttachment(ctx, diskConfig)
	if err != nil {
		return nil, false, fmt.Errorf("failed to create/get attachment: %w", err)
	}

	// Get or create a new mount in the attachment partition.
	if _, err = m.getOrCreateMount(att, mountConfig); err != nil {
		return nil, false, fmt.Errorf("failed to create/get mount: %w", err)
	}

	// Look up or create the mapping. The early guard above already verified
	// that any pre-existing mapping is compatible.
	resolvedMapping, isExisting := m.mappingMap[mappingID]
	if !isExisting {
		resolvedMapping = &mapping{att: att, partition: mountConfig.Partition}
		m.mappingMap[mappingID] = resolvedMapping
	}

	// If the mapping already existed and the disk is fully attached and mounted,
	// this is an idempotent re-call — signal the caller to return the existing guest path.
	if isExisting && att.state == attachAttached {
		if mnt, ok := att.partitions[resolvedMapping.partition]; ok && mnt.state == mountMounted {
			return resolvedMapping, true, nil
		}
	}

	return resolvedMapping, false, nil
}

// getOrCreateAttachment returns the existing attachment for the given host path
// or allocates the first free SCSI slot and creates a new one.
func (m *Manager) getOrCreateAttachment(ctx context.Context, diskConfig *DiskConfig) (*attachment, error) {
	// Look for an existing attachment whose host path matches.
	for _, existing := range m.attachmentMap {
		if existing == nil || existing.diskConfig == nil ||
			existing.diskConfig.HostPath != diskConfig.HostPath {
			continue
		}

		// A matching host path was found. If the attachment is in teardown state
		// it must not be re-used. Surface the state so the
		// caller can finish tearing down (via UnmapFromGuest) before re-mapping.
		if existing.state != attachPending && existing.state != attachAttached {
			return nil, fmt.Errorf(
				"attachment for %q is in state %s: complete teardown via UnmapFromGuest before re-mapping",
				diskConfig.HostPath, existing.state)
		}

		// Reusable attachment found; verify the full config is identical.
		if !existing.diskConfig.equals(*diskConfig) {
			return nil, fmt.Errorf("disk config conflict for %q: existing and requested configs differ", diskConfig.HostPath)
		}
		return existing, nil
	}

	// No reusable attachment exists. Scan controller/LUN pairs for a free slot.
	for controller := range m.numControllers {
		for lun := range numLUNsPerController {
			slot := VMSlot{Controller: uint(controller), LUN: uint(lun)}
			if _, occupied := m.attachmentMap[slot]; occupied {
				continue
			}

			log.G(ctx).WithFields(logrus.Fields{
				logfields.Controller: controller,
				logfields.LUN:        lun,
			}).Debug("allocating new SCSI slot")

			// Create the attachment in pending state; it will transition to
			// attached once the disk is added to the VM SCSI bus.
			att := &attachment{
				controller: uint(controller),
				lun:        uint(lun),
				diskConfig: diskConfig,
				state:      attachPending,
				partitions: make(map[uint64]*mount),
			}
			m.attachmentMap[slot] = att
			return att, nil
		}
	}

	return nil, errors.New("no available scsi slot")
}

// getOrCreateMount returns either an existing mount or creates a new one in
// the requested partition of the attachment.
func (m *Manager) getOrCreateMount(att *attachment, mountConfig *MountConfig) (*mount, error) {
	// Try to find the existing partition in the attachment.
	partition := mountConfig.Partition
	if existing, ok := att.partitions[partition]; ok {
		// If we found the partition, ensure that the config is same as requested.
		if !existing.config.equals(*mountConfig) {
			return nil, fmt.Errorf("mount config conflict for partition %d at controller=%d lun=%d: existing and requested configs differ",
				partition, att.controller, att.lun)
		}
		return existing, nil
	}

	// We did not find an existing partition, create a new guest path
	// and add the mount into the attachment partition.
	guestPath := fmt.Sprintf(mountFmt, m.nextMountIdx)
	m.nextMountIdx++

	mnt := &mount{
		config:    mountConfig,
		guestPath: guestPath,
		state:     mountPending,
		refCount:  0, // ref-count incremented after mount.
	}
	att.partitions[partition] = mnt
	return mnt, nil
}

// parseEVDPath splits an EVD host path of the form "evd://<type>/<mountPath>" into
// its EVD provider type and the underlying mount path.
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
