//go:build windows

// Package vm provides abstractions for managing virtual machines. At its core it provides two main things:
// - A Config type that can be used to configure a new VM.
// - Nicely-typed functions for making post-creation modifications to the VM.
//
// This package only supports HCS VMs for now. It could be extended to support others in the future,
// though in this case it may be best to make VM an interface that is implemented by types in other packages.
package vm

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Microsoft/hcsshim/internal/hcs"
	"github.com/Microsoft/hcsshim/internal/hcs/resourcepaths"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
	"github.com/Microsoft/hcsshim/internal/schemaversion"
	"github.com/sirupsen/logrus"
)

type migrationState int

const (
	migrationNone migrationState = iota
	migrationInitialized
)

type VM struct {
	id             string
	runtimeID      guid.GUID
	hcsSystem      *hcs.System
	config         *Config
	migrationState migrationState
}

func (vm *VM) ID() string {
	return vm.id
}

func (vm *VM) Config() *Config {
	return vm.config
}

func (vm *VM) Start(ctx context.Context) error {
	if err := vm.hcsSystem.Start(ctx); err != nil {
		return err
	}
	return nil
}

func (vm *VM) Close() error {
	return vm.hcsSystem.Close()
}

func (vm *VM) ListenHVSocket(serviceID guid.GUID) (net.Listener, error) {
	return winio.ListenHvsock(&winio.HvsockAddr{
		VMID:      vm.runtimeID,
		ServiceID: serviceID,
	})
}

func (vm *VM) AddNIC(ctx context.Context, nicID string, nic NIC) error {
	req := hcsschema.ModifySettingRequest{
		RequestType:  guestrequest.RequestTypeAdd,
		ResourcePath: fmt.Sprintf(resourcepaths.NetworkResourceFormat, nicID),
		Settings: hcsschema.NetworkAdapter{
			EndpointId: nic.EndpointID,
			MacAddress: nic.MACAddress,
		},
	}
	if err := vm.hcsSystem.Modify(ctx, &req); err != nil {
		return fmt.Errorf("add NIC %s: %w", nicID, err)
	}
	vm.config.NICs[nicID] = nic
	return nil
}

func (vm *VM) RemoveNIC(ctx context.Context, nicID string) error {
	req := hcsschema.ModifySettingRequest{
		RequestType:  guestrequest.RequestTypeRemove,
		ResourcePath: fmt.Sprintf(resourcepaths.NetworkResourceFormat, nicID),
		Settings: hcsschema.NetworkAdapter{
			EndpointId: vm.config.NICs[nicID].EndpointID,
			MacAddress: vm.config.NICs[nicID].MACAddress,
		},
	}
	if err := vm.hcsSystem.Modify(ctx, &req); err != nil {
		return fmt.Errorf("add NIC %s: %w", nicID, err)
	}
	delete(vm.config.NICs, nicID)
	return nil
}

func (vm *VM) AttachSCSI(ctx context.Context, controller, lun uint, att *SCSIAttachment) error {
	req := &hcsschema.ModifySettingRequest{
		RequestType:  guestrequest.RequestTypeAdd,
		Settings:     att.toSchemaType(),
		ResourcePath: fmt.Sprintf(resourcepaths.SCSIResourceFormat, guestrequest.ScsiControllerGuids[controller], lun),
	}
	if err := vm.hcsSystem.Modify(ctx, req); err != nil {
		return err
	}
	vm.config.SCSI[controller][lun] = *att
	return nil
}

func (vm *VM) DetachSCSI(ctx context.Context, controller, lun uint) error {
	req := &hcsschema.ModifySettingRequest{
		RequestType:  guestrequest.RequestTypeRemove,
		ResourcePath: fmt.Sprintf(resourcepaths.SCSIResourceFormat, guestrequest.ScsiControllerGuids[controller], lun),
	}
	if err := vm.hcsSystem.Modify(ctx, req); err != nil {
		return err
	}
	delete(vm.config.SCSI[controller], lun)
	return nil
}

func (vm *VM) WaitCtx(ctx context.Context) error {
	return vm.hcsSystem.WaitCtx(ctx)
}

func (vm *VM) Terminate(ctx context.Context) error {
	return vm.hcsSystem.Terminate(ctx)
}

func (vm *VM) Pause(ctx context.Context) error {
	if err := vm.hcsSystem.Pause(ctx); err != nil {
		return err
	}
	return nil
}

func (vm *VM) Save(ctx context.Context, path string) error {
	if err := vm.hcsSystem.Save(ctx, &hcsschema.SaveOptions{SaveStateFilePath: path}); err != nil {
		return err
	}
	return nil
}

func NewVM(ctx context.Context, id string, config *Config, opts ...Opt) (_ *VM, err error) {
	var oc optConfig
	for _, o := range opts {
		o(&oc)
	}

	if err := validate(config, &oc); err != nil {
		return nil, err
	}

	var system *hcs.System
	if oc.openID == "" {
		doc, err := convertConfig(config)
		if err != nil {
			return nil, err
		}
		if oc.restorePath != "" {
			doc.VirtualMachine.RestoreState = &hcsschema.RestoreState{
				SaveStateFilePath: oc.restorePath,
			}
		}
		if oc.compatData != nil {
			doc.VirtualMachine.MigrationOptions = &hcsschema.MigrationInitializeOptions{
				CompatibilityData: &hcsschema.CompatibilityInfo{
					Data: oc.compatData,
				},
			}
		}

		system, err = hcs.CreateComputeSystem(ctx, id, doc)
		if err != nil {
			return nil, err
		}
	} else {
		system, err = hcs.OpenComputeSystem(ctx, oc.openID)
		if err != nil {
			return nil, err
		}
	}
	defer func() {
		if err != nil {
			_ = system.Close()
		}
	}()
	props, err := system.Properties(ctx)
	if err != nil {
		return nil, err
	}

	vm := &VM{
		id:             id,
		runtimeID:      props.RuntimeID,
		hcsSystem:      system,
		config:         config,
		migrationState: migrationNone,
	}

	return vm, nil
}

func validate(config *Config, oc *optConfig) error {
	var count int
	if oc.restorePath != "" {
		count++
	}
	if oc.compatData != nil {
		count++
	}
	if oc.openID != "" {
		count++
	}
	if count > 1 {
		return fmt.Errorf("only one of restore/LM/open is allowed")
	}

	// Setup empty maps.
	if config.SCSI == nil {
		config.SCSI = make(map[uint]SCSIController)
	}
	if config.NICs == nil {
		config.NICs = make(map[string]NIC)
	}

	return nil
}

func convertConfig(config *Config) (*hcsschema.ComputeSystem, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}

	bootFilesDir := filepath.Join(filepath.Dir(exe), "LinuxBootFiles")
	_, err = os.Stat(bootFilesDir)
	if err != nil {
		return nil, err
	}

	doc := &hcsschema.ComputeSystem{
		Owner:                             filepath.Base(exe),
		SchemaVersion:                     schemaversion.SchemaV21(),
		ShouldTerminateOnLastHandleClosed: true,
		VirtualMachine: &hcsschema.VirtualMachine{
			StopOnReset: true,
			Chipset: &hcsschema.Chipset{
				LinuxKernelDirect: &hcsschema.LinuxKernelDirect{
					KernelFilePath: filepath.Join(bootFilesDir, "vmlinux"),
					InitRdPath:     filepath.Join(bootFilesDir, "initrd.img"),
					// KernelCmdLine:  fmt.Sprintf("init=/init 8250_core.nr_uarts=1 8250_core.skip_txen_test=1 console=ttyS0,115200 panic=-1 debug pci=off nr_cpus=%d brd.rd_nr=0 pmtmr=0 printk.devkmsg=on -- -e 1 sh -c \"/bin/gcs -v4 /log-format json -loglevel debug & exec sh\"", config.ProcessorCount),
					KernelCmdLine: fmt.Sprintf("init=/init 8250_core.nr_uarts=1 8250_core.skip_txen_test=1 console=ttyS0,115200 panic=-1 debug pci=off nr_cpus=%d brd.rd_nr=0 pmtmr=0 printk.devkmsg=on -- -e 1 /bin/gcs -v4 /log-format json -loglevel debug", config.ProcessorCount),
				},
			},
			ComputeTopology: &hcsschema.Topology{
				Memory: &hcsschema.Memory2{
					SizeInMB:        (config.MemoryMB + 1) &^ 1,
					AllowOvercommit: config.VABacked,
				},
				Processor: &hcsschema.Processor2{
					Count: config.ProcessorCount,
				},
			},
			Devices: &hcsschema.Devices{
				HvSocket: &hcsschema.HvSocket2{
					HvSocketConfig: &hcsschema.HvSocketSystemConfig{
						// Allow administrators and SYSTEM to bind to vsock sockets
						// so that we can create a GCS log socket.
						DefaultBindSecurityDescriptor: "D:P(A;;FA;;;SY)(A;;FA;;;BA)",
						ServiceTable: map[string]hcsschema.HvSocketServiceConfig{
							"0000006d-facb-11e6-bd58-64006a7986d3": {
								BindSecurityDescriptor: "D:P(A;;FA;;;SY)(A;;FA;;;BA)",
								AllowWildcardBinds:     true,
							},
						},
					},
				},
			},
		},
	}

	if len(config.SCSI) > 0 {
		doc.VirtualMachine.Devices.Scsi = make(map[string]hcsschema.Scsi)
		for controllerID, controllerConfig := range config.SCSI {
			controller := hcsschema.Scsi{
				Attachments: make(map[string]hcsschema.Attachment),
			}
			for lun, attConfig := range controllerConfig {
				controller.Attachments[fmt.Sprintf("%d", lun)] = *attConfig.toSchemaType()
			}
			if controllerID >= uint(len(guestrequest.ScsiControllerGuids)) {
				return nil, fmt.Errorf("SCSI controller index out of supported range: %d", controllerID)
			}
			doc.VirtualMachine.Devices.Scsi[guestrequest.ScsiControllerGuids[controllerID]] = controller
		}
	}

	if len(config.NICs) > 0 {
		doc.VirtualMachine.Devices.NetworkAdapters = make(map[string]hcsschema.NetworkAdapter)
		for nicID, nicConfig := range config.NICs {
			doc.VirtualMachine.Devices.NetworkAdapters[nicID] = hcsschema.NetworkAdapter{
				EndpointId: nicConfig.EndpointID,
				MacAddress: nicConfig.MACAddress,
			}
		}
	}

	if config.Serial != "" {
		doc.VirtualMachine.Devices.ComPorts = map[string]hcsschema.ComPort{
			"0": {
				NamedPipe: config.Serial,
			},
		}
	}

	return doc, nil
}

type optConfig struct {
	restorePath string
	compatData  []byte
	openID      string
}

type Opt func(*optConfig)

func WithRestore(path string) Opt {
	return func(oc *optConfig) {
		oc.restorePath = path
	}
}

func WithLM(compatData []byte) Opt {
	return func(oc *optConfig) {
		oc.compatData = compatData
	}
}

func WithOpen(id string) Opt {
	return func(oc *optConfig) {
		oc.openID = id
	}
}

type Config struct {
	ProcessorCount int32
	MemoryMB       uint64
	VABacked       bool
	SCSI           map[uint]SCSIController
	NICs           map[string]NIC
	CompatData     []byte
	Serial         string
}

type SCSIController map[uint]SCSIAttachment

type SCSIAttachment struct {
	Type     SCSIAttachmentType
	Path     string
	ReadOnly bool
	EVDType  string
}

func (att *SCSIAttachment) toSchemaType() *hcsschema.Attachment {
	st := hcsschema.Attachment{
		Path:                      att.Path,
		ReadOnly:                  att.ReadOnly,
		ExtensibleVirtualDiskType: att.EVDType,
	}
	switch att.Type {
	case SCSIAttachmentTypeVHD:
		st.Type_ = "VirtualDisk"
	case SCSIAttachmentTypePassThru:
		st.Type_ = "PassThru"
	case SCSIAttachmentTypeEVD:
		st.Type_ = "ExtensibleVirtualDisk"
	}
	return &st
}

type SCSIAttachmentType uint

const (
	SCSIAttachmentTypeVHD SCSIAttachmentType = iota
	SCSIAttachmentTypePassThru
	SCSIAttachmentTypeEVD
)

type NIC struct {
	EndpointID string
	MACAddress string
}

func (vm *VM) LMPrepare(ctx context.Context) ([]byte, error) {
	if vm.migrationState == migrationNone {
		err := vm.hcsSystem.HcsInitializeLiveMigrationOnSource(ctx)
		if err != nil {
			return nil, err
		}

		vm.migrationState = migrationInitialized
	}

	props, err := vm.hcsSystem.PropertiesV3(ctx, &hcsschema.PropertyQuery{
		Queries: map[string]interface{}{
			"CompatibilityInfo": nil,
		}})
	if err != nil {
		return nil, err
	}

	return []byte(props.Responses.CompatibilityInfo.Response.Data), nil
}

func (vm *VM) LMTransfer(ctx context.Context, socket uintptr, isSource bool) error {
	logrus.Info("starting VM for transfer")
	if isSource {
		if err := vm.hcsSystem.HcsStartLiveMigrationOnSource(ctx, socket, 1); err != nil {
			return err
		}
	} else {
		if err := vm.hcsSystem.StartWithOpts(ctx, hcs.WithLM(socket, 1)); err != nil {
			return err
		}
	}
	logrus.Info("starting VM memory transfer")
	if err := vm.hcsSystem.HcsStartLiveMigrationTransfer(ctx); err != nil {
		return err
	}
	return nil
}

func (vm *VM) LMFinalize(ctx context.Context, resume bool) error {
	if err := vm.hcsSystem.HcsFinalizeLiveMigation(ctx, resume); err != nil {
		return err
	}
	return nil
}
