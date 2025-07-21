package state

import (
	"encoding/json"
	"os"

	vm "github.com/Microsoft/hcsshim/internal/vm2"
)

func Write[T any](path string, state *T) error {
	j, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, j, 0644); err != nil {
		return err
	}
	return nil
}

func Read[T any](path string) (*T, error) {
	v := new(T)
	j, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(j, v); err != nil {
		return nil, err
	}
	return v, nil
}

func VMConfigToInternal(in *VMConfig) *vm.Config {
	var out vm.Config
	out.ProcessorCount = in.VpCount
	out.MemoryMB = in.MemCountMb
	out.VABacked = in.VaBacked
	out.SCSI = make(map[uint]vm.SCSIController)
	for i, c := range in.Scsi {
		controller := make(vm.SCSIController)
		for j, l := range c.Attachments {
			controller[uint(j)] = vm.SCSIAttachment{
				Type:     SCSIAttachmentTypeToInternal(l.Type),
				Path:     l.Path,
				ReadOnly: l.ReadOnly,
				EVDType:  l.EvdType,
			}
		}
		out.SCSI[uint(i)] = controller
	}
	out.NICs = make(map[string]vm.NIC)
	for id, nic := range in.Nics {
		out.NICs[id] = vm.NIC{
			EndpointID: nic.EndpointId,
			MACAddress: nic.MacAddress,
		}
	}
	return &out
}

func SCSIAttachmentTypeToInternal(in SCSIAttachment_AttachmentType) vm.SCSIAttachmentType {
	switch in {
	case SCSIAttachment_VirtualDisk:
		return vm.SCSIAttachmentTypeVHD
	case SCSIAttachment_PassThru:
		return vm.SCSIAttachmentTypePassThru
	case SCSIAttachment_ExtensibleVirtualDisk:
		return vm.SCSIAttachmentTypeEVD
	default:
		panic("bad attachment type")
	}
}

func VMConfigFromInternal(in *vm.Config) *VMConfig {
	out := &VMConfig{
		VpCount:    in.ProcessorCount,
		MemCountMb: in.MemoryMB,
		VaBacked:   in.VABacked,
	}
	out.Scsi = make(map[uint32]*SCSIController)
	for i, c := range in.SCSI {
		controller := &SCSIController{Attachments: make(map[uint32]*SCSIAttachment)}
		for j, l := range c {
			controller.Attachments[uint32(j)] = &SCSIAttachment{
				Type:     SCSIAttachmentTypeFromInternal(l.Type),
				Path:     l.Path,
				ReadOnly: l.ReadOnly,
				EvdType:  l.EVDType,
			}
		}
		out.Scsi[uint32(i)] = controller
	}
	out.Nics = make(map[string]*NIC)
	for id, nic := range in.NICs {
		out.Nics[id] = &NIC{
			EndpointId: nic.EndpointID,
			MacAddress: nic.MACAddress,
		}
	}
	return out
}

func SCSIAttachmentTypeFromInternal(in vm.SCSIAttachmentType) SCSIAttachment_AttachmentType {
	switch in {
	case vm.SCSIAttachmentTypeVHD:
		return SCSIAttachment_VirtualDisk
	case vm.SCSIAttachmentTypePassThru:
		return SCSIAttachment_PassThru
	case vm.SCSIAttachmentTypeEVD:
		return SCSIAttachment_ExtensibleVirtualDisk
	default:
		panic("bad attachment type")
	}
}
