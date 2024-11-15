package linuxvm

import (
	"context"
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Microsoft/hcsshim/internal/core"
	"github.com/Microsoft/hcsshim/internal/guestmanager"
	"github.com/Microsoft/hcsshim/internal/hns"
	statepkg "github.com/Microsoft/hcsshim/internal/state"
	vm "github.com/Microsoft/hcsshim/internal/vm2"
	vmpkg "github.com/Microsoft/hcsshim/internal/vm2"
	"github.com/Microsoft/hcsshim/internal/wclayer"
	"github.com/sirupsen/logrus"
)

func (s *Sandbox) LMPrepare(ctx context.Context) (_ *statepkg.SandboxState, _ *core.Resources, err error) {
	compatInfo, err := s.vm.LMPrepare(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			// s.LMCancel(ctx)
		}
	}()
	g, err := guid.NewV4()
	if err != nil {
		return nil, nil, err
	}
	resources := &core.Resources{Layers: []*core.LayersResource{{ResourceID: g.String(), ContainerID: "SandboxID"}}}
	for cid := range s.ctrs {
		g, err := guid.NewV4()
		if err != nil {
			return nil, nil, err
		}
		resources.Layers = append(resources.Layers, &core.LayersResource{ResourceID: g.String(), ContainerID: cid})
	}
	var intResources []*statepkg.Resource
	for id, r := range s.translator.resources {
		var roLayers []*statepkg.Resource_Layers_SCSI
		for _, l := range r.readOnlyLayers {
			roLayers = append(roLayers, &statepkg.Resource_Layers_SCSI{
				Controller: uint32(l.controller),
				Lun:        uint32(l.lun),
			})
		}
		intR := &statepkg.Resource{
			Type: &statepkg.Resource_Layers_{
				Layers: &statepkg.Resource_Layers{
					TaskId: id,
					Scratch: &statepkg.Resource_Layers_SCSI{
						Controller: uint32(r.scratchLayer.controller),
						Lun:        uint32(r.scratchLayer.lun),
					},
					ReadOnlyLayers: roLayers,
				},
			},
		}
		intResources = append(intResources, intR)
	}
	s.isLMSrc = true
	vmConfig := s.vm.Config()
	vmConfig.NICs = nil
	s.state = &statepkg.SandboxState{
		Vm: &statepkg.VMState{
			Config:     statepkg.VMConfigFromInternal(vmConfig),
			CompatInfo: compatInfo,
			Resources:  intResources,
		},
		Agent:  s.gm.State(),
		Ifaces: s.ifaces,
	}
	return s.state, resources, nil
}

func (s *Sandbox) LMTransfer(ctx context.Context, socket uintptr) (core.Migrated, error) {
	if err := s.vm.LMTransfer(ctx, socket, s.isLMSrc); err != nil {
		return nil, err
	}
	return &migrated{
		vm:          s.vm,
		agentConfig: s.gm.State(),
	}, nil
}

type migrated struct {
	vm          *vm.VM
	agentConfig *statepkg.GCState
	newNetNS    string
	oldIfaces   []*statepkg.GuestInterface
}

func (m *migrated) LMComplete(ctx context.Context) (core.Sandbox, error) {
	if err := m.vm.LMFinalize(ctx, true); err != nil {
		return nil, err
	}
	return newSandbox(ctx, m.vm, m.agentConfig, m.newNetNS, m.oldIfaces)
}

func (m *migrated) LMKill(ctx context.Context) error {
	if err := m.vm.LMFinalize(ctx, false); err != nil {
		return err
	}
	return nil
}

type migrator struct {
	vm           *vm.VM
	sandboxState *statepkg.SandboxState
	netns        string
}

func NewMigrator(ctx context.Context, id string, config *statepkg.SandboxState, netns string, annos map[string]string) (_ core.Migrator, err error) {
	logrus.WithField("config", config).Info("creating lm sandbox with config")
	vmConfig := statepkg.VMConfigToInternal(config.Vm.Config)
	vmConfig.Serial = annos["io.microsoft.virtualmachine.console.pipe"]
	vmID := fmt.Sprintf("%s@vm", id)
	for _, controller := range vmConfig.SCSI {
		for _, att := range controller {
			if att.Type == vm.SCSIAttachmentTypeVHD || att.Type == vm.SCSIAttachmentTypePassThru {
				if err := wclayer.GrantVmAccess(ctx, vmID, att.Path); err != nil {
					return nil, fmt.Errorf("grant vm access to %s: %w", att.Path, err)
				}
			}
		}
	}
	vm, err := vm.NewVM(ctx, vmID, vmConfig, vm.WithLM(config.Vm.CompatInfo))
	if err != nil {
		return nil, err
	}
	return &migrator{
		vm:           vm,
		sandboxState: config,
		netns:        netns,
	}, nil
}

func (m *migrator) LMTransfer(ctx context.Context, socket uintptr) (core.Migrated, error) {
	if err := m.vm.LMTransfer(ctx, socket, false); err != nil {
		return nil, err
	}
	return &migrated{
		vm:          m.vm,
		agentConfig: m.sandboxState.Agent,
		newNetNS:    m.netns,
		oldIfaces:   m.sandboxState.Ifaces,
	}, nil
}

func newSandbox(ctx context.Context, vm *vm.VM, agentConfig *statepkg.GCState, newNetNS string, oldIFaces []*statepkg.GuestInterface) (core.Sandbox, error) {
	gm, err := guestmanager.NewLinuxManagerFromState(
		func(port uint32) (net.Listener, error) { return vm.ListenHVSocket(winio.VsockServiceID(port)) },
		agentConfig)
	if err != nil {
		return nil, err
	}

	if err := gm.Start(ctx, false); err != nil {
		return nil, err
	}
	for _, iface := range oldIFaces {
		if err := gm.RemoveNetworkInterface(ctx, iface.Nsid, iface.Id); err != nil {
			return nil, fmt.Errorf("remove iface %s from ns %s: %w", iface.Id, iface.Nsid, err)
		}
	}
	var ifaces []*statepkg.GuestInterface
	if newNetNS != "" {
		endpoints, err := hns.GetNamespaceEndpoints(newNetNS)
		if err != nil {
			return nil, fmt.Errorf("find netns endpoints: %w", err)
		}
		for _, endpointID := range endpoints {
			endpoint, err := hns.GetHNSEndpointByID(endpointID)
			if err != nil {
				return nil, err
			}
			g, err := guid.NewV4()
			if err != nil {
				return nil, err
			}
			if err := vm.AddNIC(ctx, g.String(), vmpkg.NIC{EndpointID: endpoint.Id, MACAddress: endpoint.MacAddress}); err != nil {
				return nil, err
			}
			if err := gm.AddNetworkInterface(ctx, guestNamespaceID.String(), g.String(), &guestmanager.InterfaceConfig{
				MACAddress:      endpoint.MacAddress,
				IPAddress:       endpoint.IPAddress.String(),
				PrefixLength:    endpoint.PrefixLength,
				GatewayAddress:  endpoint.GatewayAddress,
				DNSSuffix:       endpoint.DNSSuffix,
				DNSServerList:   endpoint.DNSServerList,
				EnableLowMetric: endpoint.EnableLowMetric,
				EncapOverhead:   endpoint.EncapOverhead,
			}); err != nil {
				return nil, err
			}
			ifaces = append(ifaces, &statepkg.GuestInterface{Nsid: guestNamespaceID.String(), Id: g.String()})
		}
	}

	return &Sandbox{
		vm: vm,
		gm: gm,
		gt: newGuestThing(gm),
		translator: &translator{
			vm:             vm,
			scsiAttacher:   nil,
			allowMigration: true,
			resources:      make(map[string]resourceUseLayers),
		},
		waitCh: make(chan struct{}),
		ifaces: ifaces,
	}, nil
}
