package linuxvm

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Microsoft/hcsshim/internal/cmd"
	"github.com/Microsoft/hcsshim/internal/core"
	"github.com/Microsoft/hcsshim/internal/guestmanager"
	"github.com/Microsoft/hcsshim/internal/hns"
	"github.com/Microsoft/hcsshim/internal/layers"
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
	var resources core.Resources
	var intResources []*statepkg.Resource
	for id, r := range s.translator.resources {
		g, err := guid.NewV4()
		if err != nil {
			return nil, nil, err
		}
		resources.Layers = append(resources.Layers, &core.LayersResource{ResourceID: g.String(), ContainerID: id})

		var roLayers []*statepkg.Resource_Layers_SCSI
		for _, l := range r.readOnlyLayers {
			roLayers = append(roLayers, &statepkg.Resource_Layers_SCSI{
				Controller: uint32(l.controller),
				Lun:        uint32(l.lun),
			})
		}
		intR := &statepkg.Resource{
			ResourceId: g.String(),
			Type: &statepkg.Resource_Layers_{
				Layers: &statepkg.Resource_Layers{
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
	containers := make(map[string]*statepkg.Container)
	for id, ctr := range s.ctrs {
		containers[id] = &statepkg.Container{
			InitPid: uint32(ctr.Pid()),
		}
	}
	s.state = &statepkg.SandboxState{
		SandboxId: s.id,
		Vm: &statepkg.VMState{
			Config:     statepkg.VMConfigFromInternal(vmConfig),
			CompatInfo: compatInfo,
			Resources:  intResources,
		},
		Agent:      s.gm.State(),
		Ifaces:     s.ifaces,
		Containers: containers,
	}
	return s.state, &resources, nil
}

func (s *Sandbox) LMTransfer(ctx context.Context, socket uintptr) (core.Migrated, error) {
	s.waitCancel()
	if err := s.vm.LMTransfer(ctx, socket, s.isLMSrc); err != nil {
		return nil, err
	}
	return &migrated{
		vm:          s.vm,
		agentConfig: s.gm.State(),
	}, nil
}

type migrated struct {
	vm               *vm.VM
	sandboxID        string
	sandboxContainer *statepkg.Container
	agentConfig      *statepkg.GCState
	newNetNS         string
	oldIfaces        []*statepkg.GuestInterface
}

func (m *migrated) LMComplete(ctx context.Context) (core.Sandbox, error) {
	for _, controller := range m.vm.Config().SCSI {
		for _, att := range controller {
			if att.Type == vm.SCSIAttachmentTypeVHD || att.Type == vm.SCSIAttachmentTypePassThru {
				if err := wclayer.GrantVmAccess(ctx, m.vm.ID(), att.Path); err != nil {
					return nil, fmt.Errorf("grant vm access to %s: %w", att.Path, err)
				}
			}
		}
	}
	if err := m.vm.LMFinalize(ctx, true); err != nil {
		return nil, err
	}
	return newSandbox(ctx, m.vm, m.sandboxID, m.sandboxContainer, m.agentConfig, m.newNetNS, m.oldIfaces)
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

func NewMigrator(ctx context.Context, id string, config *statepkg.SandboxState, netns string, annos map[string]string, replacements *core.Replacements) (_ core.Migrator, err error) {
	logrus.WithField("config", config).Info("creating lm sandbox with config")
	vmConfig := statepkg.VMConfigToInternal(config.Vm.Config)
	vmConfig.Serial = annos["io.microsoft.virtualmachine.console.pipe"]

	for _, replacement := range replacements.Layers {
		for _, resource := range config.Vm.Resources {
			if replacement.ResourceID == resource.ResourceId {
				resource, ok := resource.Type.(*statepkg.Resource_Layers_)
				if !ok {
					return nil, fmt.Errorf("resource %s must be layers", replacement.ResourceID)
				}
				if len(replacement.Layers.Layers) != len(resource.Layers.ReadOnlyLayers) {
					return nil, fmt.Errorf("mismatched number of layers in resource %s", replacement.ResourceID)
				}
				replace := func(controller, lun uint, replacement layers.LCOWLayer2) error {
					att := vmConfig.SCSI[controller][lun]
					switch v := replacement.(type) {
					case *layers.LCOWLayerVHD:
						att.Path = v.VHDPath
					default:
						return fmt.Errorf("invalid layer type: %T", v)
					}
					vmConfig.SCSI[controller][lun] = att
					return nil
				}
				if err := replace(uint(resource.Layers.Scratch.Controller), uint(resource.Layers.Scratch.Lun), replacement.Layers.Scratch); err != nil {
					return nil, fmt.Errorf("error replacing resource %s: %w", replacement.ResourceID, err)
				}
				for i, resourceLayer := range resource.Layers.ReadOnlyLayers {
					if err := replace(uint(resourceLayer.Controller), uint(resourceLayer.Lun), replacement.Layers.Layers[i]); err != nil {
						return nil, fmt.Errorf("error replacing resource %s: %w", replacement.ResourceID, err)
					}
				}
			}
		}
	}

	vmID := fmt.Sprintf("%s@vm", id)
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
		vm:               m.vm,
		sandboxID:        m.sandboxState.SandboxId,
		sandboxContainer: m.sandboxState.Containers[m.sandboxState.SandboxId],
		agentConfig:      m.sandboxState.Agent,
		newNetNS:         m.netns,
		oldIfaces:        m.sandboxState.Ifaces,
	}, nil
}

func newSandbox(ctx context.Context, vm *vm.VM, sandboxID string, sandboxContainer *statepkg.Container, agentConfig *statepkg.GCState, newNetNS string, oldIFaces []*statepkg.GuestInterface) (core.Sandbox, error) {
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

	waitCtx, waitCancel := context.WithCancel(context.Background())
	gt := newGuestThing(gm)
	pauseCtr, err := restoreContainer(ctx, gt, waitCtx, sandboxID, sandboxContainer.InitPid, nil)
	if err != nil {
		return nil, err
	}

	sandbox := &Sandbox{
		vm: vm,
		gm: gm,
		gt: gt,
		translator: &translator{
			vm:             vm,
			scsiAttacher:   nil,
			allowMigration: true,
			resources:      make(map[string]resourceUseLayers),
		},
		waitCh:     make(chan struct{}),
		ifaces:     ifaces,
		waitCtx:    waitCtx,
		waitCancel: waitCancel,
		pauseCtr:   pauseCtr,
	}
	go sandbox.waitBackground()
	return sandbox, nil
}

func restoreContainer(ctx context.Context, gt *guestThing, waitCtx context.Context, cid string, pid uint32, myIO cmd.UpstreamIO) (*ctr, error) {
	innerCtr, err := gt.OpenContainer(ctx, cid)
	if err != nil {
		return nil, err
	}
	var (
		stdin          io.Reader
		stdout, stderr io.Writer
	)
	if myIO != nil {
		stdin = myIO.Stdin()
		stdout = myIO.Stdout()
		stderr = myIO.Stderr()
	}
	cmd, err := cmd.Open(ctx, innerCtr, pid, stdin, stdout, stderr)
	if err != nil {
		return nil, err
	}
	p := newProcess(cmd, myIO)
	c := &ctr{
		innerCtr: innerCtr,
		init:     p,
		io:       myIO,
		waitCh:   make(chan struct{}),
		waitCtx:  waitCtx,
	}
	go p.waitBackground()
	go c.waitBackground()
	return c, nil
}

func (s *Sandbox) RestoreLinuxContainer(ctx context.Context, cid string, pid uint32, myIO cmd.UpstreamIO) (core.Ctr, error) {
	c, err := restoreContainer(ctx, s.gt, s.waitCtx, cid, pid, myIO)
	if err != nil {
		return nil, err
	}
	return c, nil
}
