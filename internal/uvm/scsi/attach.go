package scsi

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	"github.com/sirupsen/logrus"
)

type AttachManager struct {
	m                    sync.Mutex
	attacher             attacher
	unplugger            unplugger
	mountManager         *MountManager
	numControllers       int
	numLUNsPerController int
	slots                [][]*attachment
}

func NewAttachManager(attacher attacher, unplugger unplugger, numControllers, numLUNsPerController int, reservedSlots []Slot, mountManager *MountManager) *AttachManager {
	slots := make([][]*attachment, numControllers)
	for i := range slots {
		slots[i] = make([]*attachment, numLUNsPerController)
	}
	for _, reservedSlot := range reservedSlots {
		// Mark the slot as already filled so we don't try to re-use it.
		// The nil attachConfig should mean it never matches a prospective new attach.
		// The refCount of 1 should not strictly be needed, since we will never get a
		// remove call for this slot, but is done for added safety.
		slots[reservedSlot.Controller][reservedSlot.LUN] = &attachment{refCount: 1}
	}
	return &AttachManager{
		attacher:             attacher,
		unplugger:            unplugger,
		mountManager:         mountManager,
		numControllers:       numControllers,
		numLUNsPerController: numLUNsPerController,
		slots:                slots,
	}
}

type attachment struct {
	controller uint
	lun        uint
	config     *AttachConfig
	waitErr    error
	waitCh     chan struct{}
	refCount   uint
}

type AttachConfig struct {
	Path     string
	ReadOnly bool
	Type     string
	EVDType  string
}

func (am *AttachManager) Attach(ctx context.Context, c *AttachConfig) (controller uint, lun uint, err error) {
	att, existed, err := am.trackAttachment(c)
	if err != nil {
		return 0, 0, err
	}
	if existed {
		select {
		case <-ctx.Done():
			return 0, 0, ctx.Err()
		case <-att.waitCh:
			if att.waitErr != nil {
				return 0, 0, att.waitErr
			}
		}
		return att.controller, att.lun, nil
	}

	defer func() {
		if err != nil {
			am.m.Lock()
			am.untrackAttachment(att)
			am.m.Unlock()
		}

		att.waitErr = err
		close(att.waitCh)
	}()

	if err := am.attacher.attach(ctx, att.controller, att.lun, att.config); err != nil {
		return 0, 0, fmt.Errorf("attach %s/%s at controller %d lun %d: %w", att.config.Type, att.config.Path, att.controller, att.lun, err)
	}
	return att.controller, att.lun, nil
}

func (am *AttachManager) Detach(ctx context.Context, controller, lun uint) (bool, error) {
	am.m.Lock()
	defer am.m.Unlock()

	logrus.Info("Detach: detaching controller %d lun %d", controller, lun)
	if controller >= uint(am.numControllers) || lun >= uint(am.numLUNsPerController) {
		return false, fmt.Errorf("controller %d lun %d out of range", controller, lun)
	}

	// First, try to unmount if we have a mount manager
	if am.mountManager != nil {
		// Find and unmount any mounts for this controller/lun
		logrus.Info("Detach: unmounting controller %d lun %d", controller, lun)
		if err := am.mountManager.UnmountByControllerLun(ctx, controller, lun); err != nil {
			logrus.Errorf("Detach: failed to unmount controller %d lun %d: %v", controller, lun, err)
			// Continue with unplug even if unmount fails
		}
	}
	logrus.Info("Detach: unmounted controller %d lun %d", controller, lun)
	att := am.slots[controller][lun]
	att.refCount--
	if att.refCount > 0 {
		return false, nil
	}

	logrus.Infof("Detach: attach manager %+v", am)
	logrus.Infof("Detach: unplugger %+v", am.unplugger)
	if am.unplugger != nil {
		if err := am.unplugger.unplug(ctx, controller, lun); err != nil {
			return false, fmt.Errorf("unplug controller %d lun %d: %w", controller, lun, err)
		}
	}
	logrus.Infof("Detach: unplugged controller %d lun %d", controller, lun)
	logrus.Infof("Detach: attacher %+v", am.attacher)
	if err := am.attacher.detach(ctx, controller, lun); err != nil {
		return false, fmt.Errorf("detach controller %d lun %d: %w", controller, lun, err)
	}
	logrus.Infof("Detach: detached controller %d lun %d", controller, lun)
	// Untrack the attachment.
	am.untrackAttachment(att)
	logrus.Infof("Detach: untracked attachment for controller %d lun %d", controller, lun)
	return true, nil
}

func (am *AttachManager) Hydrate(c *AttachConfig, controller, lun int) {
	attachRef := am.slots[controller][lun]
	if attachRef != nil && reflect.DeepEqual(c, attachRef.config) {
		attachRef.refCount++
		return
	}

	// New attachment.
	attachRef = &attachment{
		controller: uint(controller),
		lun:        uint(lun),
		config:     c,
		refCount:   1,
		waitCh:     make(chan struct{}),
	}
	am.slots[controller][lun] = attachRef
}

func (am *AttachManager) trackAttachment(c *AttachConfig) (*attachment, bool, error) {
	am.m.Lock()
	defer am.m.Unlock()

	var (
		freeController int = -1
		freeLUN        int = -1
	)
	for controller := range am.slots {
		for lun := range am.slots[controller] {
			attachment := am.slots[controller][lun]
			if attachment == nil {
				if freeController == -1 {
					freeController = controller
					freeLUN = lun
					// We don't break here, since we still might find an exact match for
					// this attachment.
				}
			} else if reflect.DeepEqual(c, attachment.config) {
				attachment.refCount++
				return attachment, true, nil
			}
		}
	}

	if freeController == -1 {
		return nil, false, ErrNoAvailableLocation
	}

	// New attachment.
	attachment := &attachment{
		controller: uint(freeController),
		lun:        uint(freeLUN),
		config:     c,
		refCount:   1,
		waitCh:     make(chan struct{}),
	}
	am.slots[freeController][freeLUN] = attachment
	return attachment, false, nil
}

// Caller must be holding am.m.
func (am *AttachManager) untrackAttachment(attachment *attachment) {
	am.slots[attachment.controller][attachment.lun] = nil
}
