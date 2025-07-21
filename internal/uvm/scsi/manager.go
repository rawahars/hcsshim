package scsi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	statepkg "github.com/Microsoft/hcsshim/internal/state"
	"github.com/Microsoft/hcsshim/internal/wclayer"
)

var (
	// ErrNoAvailableLocation indicates that a new SCSI attachment failed because
	// no new slots were available.
	ErrNoAvailableLocation = errors.New("no available location")
	// ErrNotInitialized is returned when a method is invoked on a nil [Manager].
	ErrNotInitialized = errors.New("SCSI manager not initialized")
	// ErrAlreadyReleased is returned when [Mount.Release] is called on a Mount
	// that had already been released.
	ErrAlreadyReleased = errors.New("mount was already released")
)

// Manager is the primary entrypoint for managing SCSI devices on a VM.
// It tracks the state of what devices have been attached to the VM, and
// mounted inside the guest OS.
type Manager struct {
	attachManager *AttachManager
	mountManager  *MountManager
}

// Slot represents a single SCSI slot, consisting of a controller and LUN.
type Slot struct {
	Controller uint
	LUN        uint
}

// NewManager creates a new Manager using the provided host and guest backends,
// as well as other configuration parameters.
//
// guestMountFmt is the format string to use for mounts of SCSI devices in
// the guest OS. It should have a single %d format parameter.
//
// reservedSlots indicates which SCSI slots to treat as already used. They
// will not be handed out again by the Manager.
func NewManager(
	hb HostBackend,
	gb GuestBackend,
	numControllers int,
	numLUNsPerController int,
	guestMountFmt string,
	reservedSlots []Slot,
) (*Manager, error) {
	if hb == nil || gb == nil {
		return nil, errors.New("host and guest backend must not be nil")
	}
	mm := NewMountManager(gb, guestMountFmt)
	am := NewAttachManager(hb, gb, numControllers, numLUNsPerController, reservedSlots, mm)
	return &Manager{am, mm}, nil
}

// DeviceConfig specifies the options to apply for mounting a SCSI device in
// the guest OS.
type DeviceConfig struct {
	// Partition is the target partition index on a partitioned device to
	// mount. Partitions are 1-based indexed.
	// This is only supported for LCOW.
	Partition uint64
	// Encrypted indicates if we should encrypt the device with dm-crypt.
	// This is only supported for LCOW.
	Encrypted bool
	// Options are options such as propagation options, flags, or data to
	// pass to the mount call.
	// This is only supported for LCOW.
	Options []string
	// EnsureFilesystem indicates to format the mount as `Filesystem`
	// if it is not already formatted with that fs type.
	// This is only supported for LCOW.
	EnsureFilesystem bool
	// Filesystem is the target filesystem that a device will be
	// mounted as.
	// This is only supported for LCOW.
	Filesystem string
}

// Device represents a SCSI device that has been attached to a VM, and potentially
// also mounted into the guest OS.
type Device struct {
	mgr         *Manager
	controller  uint
	lun         uint
	guestPath   string
	releaseOnce sync.Once
}

// Controller returns the controller number that the SCSI device is attached to.
func (m *Device) Controller() uint {
	return m.controller
}

// LUN returns the LUN number that the SCSI device is attached to.
func (m *Device) LUN() uint {
	return m.lun
}

// GuestPath returns the path inside the guest OS where the SCSI device was mounted.
// Will return an empty string if no guest mount was performed.
func (m *Device) GuestPath() string {
	return m.guestPath
}

// Release releases the SCSI mount. Refcount tracking is used in case multiple instances
// of the same attachment or mount are used. If the refcount for the guest OS mount
// reaches 0, the guest OS mount is removed. If the refcount for the SCSI attachment
// reaches 0, the SCSI attachment is removed.
func (m *Device) Release(ctx context.Context) (err error) {
	err = ErrAlreadyReleased
	m.releaseOnce.Do(func() {
		err = m.mgr.remove(ctx, m.controller, m.lun, m.guestPath)
	})
	return
}

// AddVirtualDisk attaches and mounts a VHD on the host to the VM. If the same
// VHD has already been attached to the VM, the existing attachment will
// be reused. If the same VHD has already been mounted in the guest OS
// with the same MountConfig, the same mount will be reused.
//
// If vmID is non-empty an ACL will be added to the VHD so that the specified VHD
// can access it.
//
// mc determines the settings to apply on the guest OS mount. If
// it is nil, no guest OS mount is performed.
func (m *Manager) AddVirtualDisk(
	ctx context.Context,
	hostPath string,
	readOnly bool,
	vmID string,
	mc *DeviceConfig,
) (*Device, error) {
	if m == nil {
		return nil, ErrNotInitialized
	}
	if vmID != "" {
		if err := wclayer.GrantVmAccess(ctx, vmID, hostPath); err != nil {
			return nil, err
		}
	}
	var mcInternal *MountConfig
	if mc != nil {
		mcInternal = &MountConfig{
			Partition:       mc.Partition,
			ReadOnly:        readOnly,
			Encrypted:       mc.Encrypted,
			Options:         mc.Options,
			EnsureFileystem: mc.EnsureFilesystem,
			Filesystem:      mc.Filesystem,
		}
	}
	return m.add(ctx,
		&AttachConfig{
			Path:     hostPath,
			ReadOnly: readOnly,
			Type:     "VirtualDisk",
		},
		mcInternal)
}

// AddPhysicalDisk attaches and mounts a physical disk on the host to the VM.
// If the same physical disk has already been attached to the VM, the existing
// attachment will be reused. If the same physical disk has already been mounted
// in the guest OS with the same MountConfig, the same mount will be reused.
//
// If vmID is non-empty an ACL will be added to the disk so that the specified VHD
// can access it.
//
// mc determines the settings to apply on the guest OS mount. If
// it is nil, no guest OS mount is performed.
func (m *Manager) AddPhysicalDisk(
	ctx context.Context,
	hostPath string,
	readOnly bool,
	vmID string,
	mc *DeviceConfig,
) (*Device, error) {
	if m == nil {
		return nil, ErrNotInitialized
	}
	if vmID != "" {
		if err := wclayer.GrantVmAccess(ctx, vmID, hostPath); err != nil {
			return nil, err
		}
	}
	var mcInternal *MountConfig
	if mc != nil {
		mcInternal = &MountConfig{
			Partition:       mc.Partition,
			ReadOnly:        readOnly,
			Encrypted:       mc.Encrypted,
			Options:         mc.Options,
			EnsureFileystem: mc.EnsureFilesystem,
			Filesystem:      mc.Filesystem,
		}
	}
	return m.add(ctx,
		&AttachConfig{
			Path:     hostPath,
			ReadOnly: readOnly,
			Type:     "PassThru",
		},
		mcInternal)
}

// AddExtensibleVirtualDisk attaches and mounts an extensible virtual disk (EVD) to the VM.
// EVDs are made available by special drivers on the host which interact with the Hyper-V
// synthetic SCSI stack.
// If the same physical disk has already been attached to the VM, the existing
// attachment will be reused. If the same physical disk has already been mounted
// in the guest OS with the same MountConfig, the same mount will be reused.
//
// hostPath must adhere to the format "evd://<evdType>/<evdMountPath>".
//
// mc determines the settings to apply on the guest OS mount. If
// it is nil, no guest OS mount is performed.
func (m *Manager) AddExtensibleVirtualDisk(
	ctx context.Context,
	hostPath string,
	readOnly bool,
	mc *DeviceConfig,
) (*Device, error) {
	if m == nil {
		return nil, ErrNotInitialized
	}
	evdType, mountPath, err := parseExtensibleVirtualDiskPath(hostPath)
	if err != nil {
		return nil, err
	}
	var mcInternal *MountConfig
	if mc != nil {
		mcInternal = &MountConfig{
			Partition:       mc.Partition,
			ReadOnly:        readOnly,
			Encrypted:       mc.Encrypted,
			Options:         mc.Options,
			EnsureFileystem: mc.EnsureFilesystem,
			Filesystem:      mc.Filesystem,
		}
	}
	return m.add(ctx,
		&AttachConfig{
			Path:     mountPath,
			ReadOnly: readOnly,
			Type:     "ExtensibleVirtualDisk",
			EVDType:  evdType,
		},
		mcInternal)
}

func (m *Manager) add(ctx context.Context, attachConfig *AttachConfig, mountConfig *MountConfig) (_ *Device, err error) {
	controller, lun, err := m.attachManager.Attach(ctx, attachConfig)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_, _ = m.attachManager.Detach(ctx, controller, lun)
		}
	}()

	var guestPath string
	if mountConfig != nil {
		guestPath, err = m.mountManager.Mount(ctx, controller, lun, mountConfig)
		if err != nil {
			return nil, err
		}
	}

	return &Device{mgr: m, controller: controller, lun: lun, guestPath: guestPath}, nil
}

func (m *Manager) remove(ctx context.Context, controller, lun uint, guestPath string) error {
	if guestPath != "" {
		removed, err := m.mountManager.Unmount(ctx, guestPath)
		if err != nil {
			return err
		}

		if !removed {
			return nil
		}
	}

	if _, err := m.attachManager.Detach(ctx, controller, lun); err != nil {
		return err
	}

	return nil
}

// parseExtensibleVirtualDiskPath parses the evd path provided in the config.
// extensible virtual disk path has format "evd://<evdType>/<evd-mount-path>"
// this function parses that and returns the `evdType` and `evd-mount-path`.
func parseExtensibleVirtualDiskPath(hostPath string) (evdType, mountPath string, err error) {
	trimmedPath := strings.TrimPrefix(hostPath, "evd://")
	separatorIndex := strings.Index(trimmedPath, "/")
	if separatorIndex <= 0 {
		return "", "", fmt.Errorf("invalid extensible vhd path: %s", hostPath)
	}
	return trimmedPath[:separatorIndex], trimmedPath[separatorIndex+1:], nil
}

type scsiStateAttachmentConfig struct {
	Path     string
	ReadOnly bool
	Type     string
}

type scsiStateAttachment struct {
	Controller uint
	LUN        uint
	Config     *scsiStateAttachmentConfig
	RefCount   uint
}

type scsiStateMountConfig struct {
	ReadOnly bool
	Options  []string
}

type scsiStateMount struct {
	Controller uint
	LUN        uint
	Path       string
	Config     scsiStateMountConfig
	RefCount   uint
}

type scsiState struct {
	Attachments []scsiStateAttachment
	Mounts      []scsiStateMount
	MountFmt    string
}

type SlotState struct {
	RefCount uint
	Path     string
	ReadOnly bool
	Type     string
	EVDType  string
}

type AttachManagerState struct {
	NumControllers       int
	NumLUNSPerController int
	Slots                map[uint]map[uint]*SlotState
}

type MountState struct {
	Index            int
	Controller       uint
	LUN              uint
	Partition        uint64
	ReadOnly         bool
	Encrypted        bool
	Options          []string
	EnsureFilesystem bool
	Filesystem       string
}

type MountManagerState struct {
	MountFmt string
	Mount    []MountState
}

type ManagerState struct {
	AttachManager *AttachManagerState
	MountManager  *MountManagerState
}

func (am *AttachManager) State() *AttachManagerState {
	ams := &AttachManagerState{
		NumControllers:       am.numControllers,
		NumLUNSPerController: am.numLUNsPerController,
		Slots:                make(map[uint]map[uint]*SlotState),
	}
	for controller, luns := range am.slots {
		for lun, att := range luns {
			ams.Slots[uint(controller)] = make(map[uint]*SlotState)
			slot := SlotState{
				RefCount: att.refCount,
				Path:     att.config.Path,
				ReadOnly: att.config.ReadOnly,
				Type:     att.config.Type,
				EVDType:  att.config.EVDType,
			}
			ams.Slots[uint(controller)][uint(lun)] = &slot
		}
	}
	return ams
}

func (mm *MountManager) State() *MountManagerState {
	mms := &MountManagerState{
		MountFmt: mm.mountFmt,
	}
	for _, m := range mm.mounts {
		mms.Mount = append(mms.Mount, MountState{
			Index:            m.index,
			Controller:       m.controller,
			LUN:              m.lun,
			Partition:        m.config.Partition,
			ReadOnly:         m.config.ReadOnly,
			Encrypted:        m.config.Encrypted,
			Options:          m.config.Options,
			EnsureFilesystem: m.config.EnsureFileystem,
			Filesystem:       m.config.Filesystem,
		})
	}
	return mms
}

func (m *Manager) Save(ctx context.Context, path string) error {
	if err := os.MkdirAll(path, 0755); err != nil {
		return err
	}
	state := scsiState{}
	for i := range m.attachManager.slots {
		for j := range m.attachManager.slots[i] {
			s := m.attachManager.slots[i][j]
			if s != nil && s.refCount > 0 {
				a := scsiStateAttachment{
					Controller: s.controller,
					LUN:        s.lun,
					RefCount:   s.refCount,
				}
				if s.config != nil {
					a.Config = &scsiStateAttachmentConfig{
						Path:     s.config.Path,
						ReadOnly: s.config.ReadOnly,
						Type:     s.config.Type,
					}
				}
				state.Attachments = append(state.Attachments, a)
			}
		}
	}
	for _, m := range m.mountManager.mounts {
		state.Mounts = append(state.Mounts, scsiStateMount{
			Controller: m.controller,
			LUN:        m.lun,
			Path:       m.path,
			Config: scsiStateMountConfig{
				ReadOnly: m.config.ReadOnly,
				Options:  m.config.Options,
			},
			RefCount: m.refCount,
		})
	}
	state.MountFmt = m.mountManager.mountFmt
	if err := statepkg.Write(filepath.Join(path, "state.json"), &state); err != nil {
		return err
	}
	return nil
}

type ManagerRestorer struct {
	state *scsiState
}

func RestoreManager(ctx context.Context, path string) (*ManagerRestorer, error) {
	state, err := statepkg.Read[scsiState](filepath.Join(path, "state.json"))
	if err != nil {
		return nil, err
	}
	return &ManagerRestorer{state}, nil
}

func (mr *ManagerRestorer) Restore(
	ctx context.Context,
	hb HostBackend,
	gb GuestBackend,
	numControllers int,
	numLUNsPerController int,
) *Manager {
	am := &AttachManager{
		attacher:             hb,
		unplugger:            gb,
		numControllers:       numControllers,
		numLUNsPerController: numLUNsPerController,
		slots:                make([][]*attachment, numControllers),
	}
	for i := range am.slots {
		am.slots[i] = make([]*attachment, numLUNsPerController)
	}
	for _, a := range mr.state.Attachments {
		am.slots[a.Controller][a.LUN] = &attachment{
			controller: a.Controller,
			lun:        a.LUN,
			config: &AttachConfig{
				Path:     a.Config.Path,
				ReadOnly: a.Config.ReadOnly,
				Type:     a.Config.Type,
			},
			waitCh:   make(chan struct{}),
			refCount: a.RefCount,
		}
		close(am.slots[a.Controller][a.LUN].waitCh)
	}
	mm := &MountManager{
		mounter:  gb,
		mounts:   make([]*mount, 0, len(mr.state.Mounts)),
		mountFmt: mr.state.MountFmt,
	}
	for i, m := range mr.state.Mounts {
		mm.mounts = append(mm.mounts, &mount{
			path:       m.Path,
			index:      i,
			controller: m.Controller,
			lun:        m.LUN,
			config: &MountConfig{
				ReadOnly: m.Config.ReadOnly,
				Options:  m.Config.Options,
			},
			waitCh:   make(chan struct{}),
			refCount: m.RefCount,
		})
		close(mm.mounts[i].waitCh)
	}
	return &Manager{am, mm}
}
