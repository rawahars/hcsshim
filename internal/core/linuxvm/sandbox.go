package linuxvm

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Microsoft/hcsshim/internal/cmd"
	"github.com/Microsoft/hcsshim/internal/core"
	"github.com/Microsoft/hcsshim/internal/guestmanager"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/hns"
	"github.com/Microsoft/hcsshim/internal/layers"
	"github.com/Microsoft/hcsshim/internal/oci"
	"github.com/Microsoft/hcsshim/internal/resources"
	statepkg "github.com/Microsoft/hcsshim/internal/state"
	"github.com/Microsoft/hcsshim/internal/uvm/scsi"
	vmpkg "github.com/Microsoft/hcsshim/internal/vm2"
	"github.com/Microsoft/hcsshim/internal/wclayer"
	"github.com/Microsoft/hcsshim/pkg/annotations"
	"github.com/opencontainers/runtime-spec/specs-go"
)

type Sandbox struct {
	vm             *vmpkg.VM
	gm             *guestmanager.LinuxManager
	gt             *guestThing
	translator     *translator
	pauseCtr       *ctr
	ctrs           map[string]*ctr
	waitCh         chan struct{}
	waitErr        error
	allowMigration bool
	netns          string
	endpoints      map[string]string // VM NIC ID -> guest interface ID
}

type translator struct {
	vm             *vmpkg.VM
	scsiAttacher   *scsi.AttachManager
	allowMigration bool
	// resources      map[ResourceKey]resourceUse
	resources map[string]resourceUseLayers
}

type linuxHostedSystem struct {
	SchemaVersion    *hcsschema.Version
	OciBundlePath    string
	OciSpecification *specs.Spec
	ScratchDirPath   string
}

// baaa389b-bfd2-4500-b972-000000000000
// base guid, chosen arbitrarily
var guestNamespaceID = guid.GUID{Data1: 0xbaaa389b, Data2: 0xbfd2, Data3: 0x4500, Data4: [8]byte{0xb9, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}

func parseAnnotationsUint64(ctx context.Context, a map[string]string, key string, def uint64) uint64 {
	if v, ok := a[key]; ok {
		countu, err := strconv.ParseUint(v, 10, 64)
		if err == nil {
			return countu
		}
	}
	return def
}

func parseAnnotationsCPUCount(ctx context.Context, s *specs.Spec, annotation string, def int32) int32 {
	if m := parseAnnotationsUint64(ctx, s.Annotations, annotation, 0); m != 0 {
		return int32(m)
	}
	if s.Windows != nil &&
		s.Windows.Resources != nil &&
		s.Windows.Resources.CPU != nil &&
		s.Windows.Resources.CPU.Count != nil &&
		*s.Windows.Resources.CPU.Count > 0 {
		return int32(*s.Windows.Resources.CPU.Count)
	}
	return def
}

func parseAnnotationsMemory(ctx context.Context, s *specs.Spec, annotation string, def uint64) uint64 {
	if m := parseAnnotationsUint64(ctx, s.Annotations, annotation, 0); m != 0 {
		return m
	}
	if s.Windows != nil &&
		s.Windows.Resources != nil &&
		s.Windows.Resources.Memory != nil &&
		s.Windows.Resources.Memory.Limit != nil &&
		*s.Windows.Resources.Memory.Limit > 0 {
		return (*s.Windows.Resources.Memory.Limit / 1024 / 1024)
	}
	return def
}

func parseAnnotationsBool(ctx context.Context, a map[string]string, key string, def bool) bool {
	if v, ok := a[key]; ok {
		switch strings.ToLower(v) {
		case "true":
			return true
		case "false":
			return false
		}
	}
	return def
}

func NewSandbox(ctx context.Context, id string, l *layers.LCOWLayers2, spec *specs.Spec) (_ core.Sandbox, err error) {
	if err := validateSpec(ctx, spec); err != nil {
		return nil, fmt.Errorf("spec validation: %w", err)
	}
	vmID := fmt.Sprintf("%s@vm", id)
	allowMigration := strings.ToLower(spec.Annotations["io.microsoft.virtualmachine.allowmigration"]) == "true"
	vmConfig := &vmpkg.Config{
		ProcessorCount: parseAnnotationsCPUCount(ctx, spec, "io.microsoft.virtualmachine.computetopology.processor.count", 1),
		MemoryMB:       parseAnnotationsMemory(ctx, spec, "io.microsoft.virtualmachine.computetopology.memory.sizeinmb", 1024),
		VABacked:       parseAnnotationsBool(ctx, spec.Annotations, "io.microsoft.virtualmachine.computetopology.memory.allowovercommit", false),
		SCSI: map[uint]vmpkg.SCSIController{
			0: vmpkg.SCSIController{},
			1: vmpkg.SCSIController{},
			2: vmpkg.SCSIController{},
			3: vmpkg.SCSIController{},
		},
	}
	vm, err := vmpkg.NewVM(ctx, vmID, vmConfig)
	if err != nil {
		return nil, err
	}
	gm, err := guestmanager.NewLinuxManager(
		func(port uint32) (net.Listener, error) { return vm.ListenHVSocket(winio.VsockServiceID(port)) },
	)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			gm.Close()
		}
	}()
	if err := gm.Start(ctx); err != nil {
		return nil, fmt.Errorf("guest manager start: %w", err)
	}
	if err := vm.Start(ctx); err != nil {
		return nil, fmt.Errorf("vm start: %w", err)
	}
	defer func() {
		if err != nil {
			vm.Close()
		}
	}()

	netns := oci.GetNetNS(spec)
	savedEndpoints := make(map[string]string)
	endpoints, err := hns.GetNamespaceEndpoints(netns)
	if err != nil {
		return nil, err
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
		savedEndpoints[endpointID] = g.String()
	}

	sa := scsi.NewAttachManager(scsi.NewVMHostBackend(vm), nil, len(vmConfig.SCSI), 64, nil)

	newSpec, err := convertSpec(spec)
	if err != nil {
		return nil, err
	}
	ctrConfig := &core.LinuxCtrConfig{
		ID:     id,
		Layers: l,
		Spec:   newSpec,
	}

	gt := newGuestThing(gm)

	translator := &translator{
		vm:             vm,
		scsiAttacher:   sa,
		allowMigration: allowMigration,
		resources:      make(map[string]resourceUseLayers),
	}
	pauseCtr, err := createCtr(ctx, ctrConfig, translator, gt)
	if err != nil {
		return nil, err
	}

	return &Sandbox{
		vm:             vm,
		gm:             gm,
		translator:     translator,
		pauseCtr:       pauseCtr,
		ctrs:           make(map[string]*ctr),
		allowMigration: allowMigration,
		netns:          netns,
		waitCh:         make(chan struct{}),
	}, nil
}

func validateSpec(ctx context.Context, spec *specs.Spec) error {
	// If migration is enabled for this sandbox, we need to do additional checking to ensure no
	// incompatible features are used.
	if oci.ParseAnnotationsBool(ctx, spec.Annotations, "io.microsoft.virtualmachine.allowmigration", false) {
		if s := func() string {
			// Deny list: Specific annotations that are not allowed.
			for _, badAnno := range []string{
				annotations.NetworkConfigProxy,
			} {
				if _, ok := spec.Annotations[badAnno]; ok {
					return fmt.Sprintf("annotation: %s", badAnno)
				}
			}
			// Allow list: Only specific annotations under io.microsoft.virtualmachine are allowed.
			for key := range spec.Annotations {
				if strings.HasPrefix(key, "io.microsoft.virtualmachine") {
					if !slices.Contains([]string{
						"io.microsoft.virtualmachine.allowmigration",
						annotations.AllowOvercommit,
						annotations.ContainerProcessorCount,
						annotations.MemorySizeInMB,
						annotations.VPMemCount,
					}, key) {
						return fmt.Sprintf("annotation: %s", key)
					}
				}
			}
			return ""
		}(); s != "" {
			return fmt.Errorf("not supported with migration: %s", s)
		}
	}
	return nil
}

func (s *Sandbox) Start(ctx context.Context) error {
	err := s.pauseCtr.Start(ctx)
	go s.waitBackground()
	return err
}

func (s *Sandbox) CreateLinuxContainer(ctx context.Context, c *core.LinuxCtrConfig) (_ core.Ctr, err error) {
	return createCtr(ctx, c, s.translator, s.gt)
}

type cleanupSet []resources.ResourceCloser

func (cs cleanupSet) Release(ctx context.Context) (retErr error) {
	for i := len(cs) - 1; i >= 0; i-- {
		if err := cs[i]; err != nil && retErr == nil {
			retErr = fmt.Errorf("encountered errors while cleaning up")
		}
	}
	return
}

func createCtr(ctx context.Context, c *core.LinuxCtrConfig, t *translator, gt *guestThing) (_ *ctr, err error) {
	gc, _, err := t.translate(ctx, c)
	if err != nil {
		return nil, err
	}

	ctr, err := gt.DoTheThing(ctx, c.ID, gc)
	// ctr, err := gm.CreateContainer(ctx, c.ID, gcsConfig)
	if err != nil {
		return nil, err
	}
	return newCtr(ctr, c.Spec.Process, c.IO), nil
}

func (t *translator) translate(ctx context.Context, c *core.LinuxCtrConfig) (_ *guestConfig, _ []resources.ResourceCloser, err error) {
	var cleanup cleanupSet
	defer func() {
		if err != nil {
			cleanup.Release(ctx)
		}
	}()

	gc := &guestConfig{
		doc:    c.Spec,
		layers: &layers.LCOWLayers2{},
	}

	var resources resourceUseLayers

	switch scratch := c.Layers.Scratch.(type) {
	case *layers.LCOWLayerVHD:
		if err := wclayer.GrantVmAccess(ctx, t.vm.ID(), scratch.VHDPath); err != nil {
			return nil, nil, err
		}
		config := &scsi.AttachConfig{Path: scratch.VHDPath, Type: "VirtualDisk"}
		controller, lun, err := t.scsiAttacher.Attach(ctx, config)
		if err != nil {
			return nil, nil, err
		}
		gc.layers.Scratch = &layers.LCOWLayerSCSI{Controller: controller, LUN: lun}
		resources.scratchLayer = scsiAttachment{controller, lun}
	default:
		return nil, nil, fmt.Errorf("unsupported layer type: %T", scratch)
	}
	for _, layer := range c.Layers.Layers {
		switch layer := layer.(type) {
		case *layers.LCOWLayerVHD:
			if err := wclayer.GrantVmAccess(ctx, t.vm.ID(), layer.VHDPath); err != nil {
				return nil, nil, err
			}
			config := &scsi.AttachConfig{Path: layer.VHDPath, Type: "VirtualDisk", ReadOnly: true}
			controller, lun, err := t.scsiAttacher.Attach(ctx, config)
			if err != nil {
				return nil, nil, err
			}
			gc.layers.Layers = append(gc.layers.Layers, &layers.LCOWLayerSCSI{Controller: controller, LUN: lun})
			resources.readOnlyLayers = append(resources.readOnlyLayers, scsiAttachment{controller, lun})
		default:
			return nil, nil, fmt.Errorf("unsupported layer type: %T", layer)
		}
	}

	c.Spec.Windows.Network.NetworkNamespace = guestNamespaceID.String()

	for _, mount := range c.Spec.Mounts {
		if t.allowMigration && !strings.HasPrefix(mount.Source, "sandbox://") {
			return nil, nil, fmt.Errorf("non-sandbox mount disallowed with migration: %s", mount.Source)
		}
	}

	t.resources[c.ID] = resources

	return gc, cleanup, nil
}

func convertSpec(oldSpec *specs.Spec) (*specs.Spec, error) {
	j, err := json.Marshal(oldSpec)
	if err != nil {
		return nil, err
	}
	var spec specs.Spec
	err = json.Unmarshal(j, &spec)
	if err != nil {
		return nil, err
	}

	spec.Windows = nil
	if oldSpec.Windows != nil {
		if oldSpec.Windows != nil && oldSpec.Windows.Network != nil && oldSpec.Windows.Network.NetworkNamespace != "" {
			netns := oldSpec.Windows.Network.NetworkNamespace
			if spec.Windows == nil {
				spec.Windows = &specs.Windows{Network: &specs.WindowsNetwork{NetworkNamespace: netns}}
			} else if spec.Windows.Network == nil {
				spec.Windows.Network = &specs.WindowsNetwork{NetworkNamespace: netns}
			} else {
				spec.Windows.Network.NetworkNamespace = netns
			}
		}
		if oldSpec.Windows != nil && oldSpec.Windows.Devices != nil {
			dev := oldSpec.Windows.Devices
			if spec.Windows == nil {
				spec.Windows = &specs.Windows{Devices: dev}
			} else {
				spec.Windows.Devices = dev
			}
		}
	}
	spec.Hooks = nil
	spec.Linux.CgroupsPath = ""
	if spec.Linux.Resources != nil {
		spec.Linux.Resources.Devices = nil
		spec.Linux.Resources.Pids = nil
		spec.Linux.Resources.BlockIO = nil
		spec.Linux.Resources.HugepageLimits = nil
		spec.Linux.Resources.Network = nil
	}

	return &spec, nil
}

func (s *Sandbox) Wait(ctx context.Context) error {
	select {
	case <-s.waitCh:
		return s.waitErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Sandbox) waitBackground() {
	s.waitErr = func() error {
		ctx := context.Background()
		if err := s.pauseCtr.Wait(ctx); err != nil {
			return err
		}
		if err := s.vm.WaitCtx(ctx); err != nil {
			return err
		}
		return nil
	}()
	close(s.waitCh)
}

func (s *Sandbox) Status() core.Status {
	var status sandboxStatus
	select {
	case <-s.waitCh:
		status.exited = true
	default:
	}
	return status
}

type sandboxStatus struct {
	exited bool
}

func (s sandboxStatus) Exited() bool {
	return s.exited
}

func (s sandboxStatus) ExitCode() int {
	return -1
}

func (s *Sandbox) Pid() int {
	return s.pauseCtr.Pid()
}

func (s *Sandbox) Terminate(ctx context.Context) error {
	return s.vm.Terminate(ctx)
}

func (s *Sandbox) CreateProcess(ctx context.Context, c *core.ProcessConfig) (core.Process, error) {
	return newProcess(&cmd.Cmd{
		Host:   s.gm,
		Spec:   c.Spec,
		Stdin:  c.IO.Stdin(),
		Stdout: c.IO.Stdout(),
		Stderr: c.IO.Stderr(),
	}, c.IO), nil
}

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
	return &statepkg.SandboxState{
		Vm: &statepkg.VMState{
			Config:     statepkg.VMConfigFromInternal(s.vm.Config()),
			CompatInfo: compatInfo,
			Resources:  intResources,
		},
		Agent: s.gm.State(),
	}, resources, nil
}

func NewLMSandbox(ctx context.Context, id string, l *layers.LCOWLayers2, spec *specs.Spec) (_ core.Sandbox, err error) {
	return nil, nil
}

func (s *Sandbox) LMTransfer(ctx context.Context, socket uintptr) error {
	return nil
}

func (s *Sandbox) LMFinalize(ctx context.Context) error {
	return nil
}

// type ResourceMap map[ResourceKey]resourceUse

// type ResourceKey interface {
// 	isResourceKey()
// }

// type ResourceKeyLayers struct {
// 	ContainerID string
// }

// func (ResourceKeyLayers) isResourceKey() {}

// type resourceUse interface {
// 	isResourceUse()
// }

type resourceUseLayers struct {
	scratchLayer   scsiAttachment
	readOnlyLayers []scsiAttachment
}

// func (resourceUseLayers) isResourceUse() {}

type scsiAttachment struct {
	controller uint
	lun        uint
}

// type migratorResource struct {
// 	value layers.LCOWLayer2
// 	use   resourceUseLayers
// }

// type ResourceOption func(map[ResourceKey]resourceUse, *vmpkg.Config) error

// func WithLayersResource(containerID string, layers *layers.LCOWLayers) ResourceOption {
// 	return func(m map[ResourceKey]resourceUse, config *vmpkg.Config) error {
// 		u := m[ResourceKeyLayers{containerID}].(resourceUseLayers)
// 		att := config.SCSI[u.scratchLayer.controller][u.scratchLayer.lun]
// 		att.Path = layers.ScratchVHDPath
// 		config.SCSI[u.scratchLayer.controller][u.scratchLayer.lun] = att
// 		for i, l := range layers.Layers {
// 			att := config.SCSI[u.readOnlyLayers[i].controller][u.readOnlyLayers[i].lun]
// 			att.Path = l.VHDPath
// 			config.SCSI[u.readOnlyLayers[i].controller][u.readOnlyLayers[i].lun] = att
// 		}
// 		return nil
// 	}
// }

// type Migrator struct {
// 	vmMig                *vmpkg.Migrator
// 	resourceReplacements []migratorResource // Value + Use
// }

// func NewMigrator(compatData []byte, resources []*save.Resource, vmState *statepkg.VMState) (*Migrator, error) {
// 	vmConfig, err := updateVMConfig(resources, vmState)
// 	if err != nil {
// 		return nil, err
// 	}
// 	vmMig, err := vmpkg.NewMigrator(vmConfig, compatData)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return &Migrator{vmMig: vmMig}, nil
// }

// func (m *Migrator) Init(ctx context.Context) error {
// 	return m.vmMig.Init(ctx)
// }

// func (m *Migrator) Start(ctx context.Context, socket windows.Handle) error {
// 	return m.vmMig.Start(ctx, socket)
// }

// func (m *Migrator) Close(ctx context.Context) error {
// 	return m.vmMig.Close(ctx)
// }

// func (m *Migrator) Complete(ctx context.Context, state any) (*Sandbox, error) {
// 	vm, err := m.vmMig.Complete(ctx)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return &Sandbox{vm: vm}, nil
// }

// func updateVMConfig(resources []*save.Resource, vmState *statepkg.VMState) (*vmpkg.Config, error) {
// 	var opts []ResourceOption
// 	for _, r := range resources {
// 		switch r := r.Type.(type) {
// 		case *save.Resource_Layers_:
// 			layers, err := layers.GetLCOWLayers([]*types.Mount{r.Layers.Mount}, nil)
// 			if err != nil {
// 				return nil, err
// 			}
// 			opts = append(opts, WithLayersResource(r.Layers.ContainerId, layers))
// 		default:
// 			return nil, fmt.Errorf("unsupported resource type: %T", r)
// 		}
// 	}
// 	var intResources map[ResourceKey]resourceUse
// 	for _, r := range vmState.Resources {
// 		switch r := r.Type.(type) {
// 		case *statepkg.Resource_Layers_:
// 			key := ResourceKeyLayers{r.Layers.ContainerId}
// 			use := resourceUseLayers{scratchLayer: scsiAttachment{uint(r.Layers.Scratch.Controller), uint(r.Layers.Scratch.Lun)}}
// 			for _, l := range r.Layers.ReadOnlyLayers {
// 				use.readOnlyLayers = append(use.readOnlyLayers, scsiAttachment{uint(l.Controller), uint(l.Lun)})
// 			}
// 			if _, ok := intResources[key]; ok {
// 				return nil, fmt.Errorf("repeat key in int resources")
// 			}
// 			intResources[key] = use
// 		default:
// 			return nil, fmt.Errorf("unsupported int resource type: %T", r)
// 		}
// 	}
// 	vmConfig := statepkg.VMConfigToInternal(vmState.Config)
// 	for _, o := range opts {
// 		if err := o(intResources, vmConfig); err != nil {
// 			return nil, err
// 		}
// 	}
// 	return vmConfig, nil
// }

// func newVM(ctx context.Context, id string, resources []*save.Resource, vmState *statepkg.VMState, savedPath string) (*vmpkg.VM, error) {
// 	vmConfig, err := updateVMConfig(resources, vmState)
// 	if err != nil {
// 		return nil, err
// 	}

// 	var vmOpts []vmpkg.Opt
// 	if savedPath != "" {
// 		vmOpts = append(vmOpts, vmpkg.WithRestore(savedPath))
// 	}

// 	vm, err := vmpkg.NewVM(ctx, id, vmConfig, vmOpts...)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return vm, nil
// }

// func RestoreSandbox(ctx context.Context, id string, netns string, path string, resources []*save.Resource, vmState *statepkg.VMState) (_ *Sandbox, err error) {
// 	vm, err := newVM(ctx, id, resources, vmState, filepath.Join(path, "vmstate"))
// 	if err != nil {
// 		return nil, err
// 	}

// 	// TODO: Draw the rest of the owl.
// 	// (connect to guest)

// 	return &Sandbox{
// 		vm: vm,
// 	}, nil
// }

// func (s *Sandbox) State(ctx context.Context) *statepkg.VMState {
// 	state := statepkg.VMState{
// 		Config:                 statepkg.VMConfigFromInternal(s.vm.Config()),
// 		ScsiControllerTracking: make(map[uint32]*statepkg.SCSIControllerTracking),
// 	}
// 	for k, u := range s.translator.resources {
// 		switch k := k.(type) {
// 		case ResourceKeyLayers:
// 			u := u.(resourceUseLayers)
// 			r := &statepkg.Resource_Layers{
// 				ContainerId: k.ContainerID,
// 				Scratch: &statepkg.Resource_Layers_SCSI{
// 					Controller: uint32(u.scratchLayer.controller),
// 					Lun:        uint32(u.scratchLayer.lun),
// 				},
// 			}
// 			for _, l := range u.readOnlyLayers {
// 				r.ReadOnlyLayers = append(r.ReadOnlyLayers, &statepkg.Resource_Layers_SCSI{
// 					Controller: uint32(l.controller),
// 					Lun:        uint32(l.lun),
// 				})
// 			}
// 			state.Resources = append(state.Resources, &statepkg.Resource{
// 				Type: &statepkg.Resource_Layers_{
// 					Layers: r,
// 				},
// 			})
// 		default:
// 			panic("unrecognized resource type")
// 		}
// 	}
// 	sms := s.translator.scsiAttacher.State()
// 	for controller, luns := range sms.Slots {
// 		for lun, att := range luns {
// 			state.ScsiControllerTracking[uint32(controller)].ScsiLunTracking[uint32(lun)] = &statepkg.SCSIAttachmentTracking{
// 				RefCount: uint32(att.RefCount),
// 			}
// 		}
// 	}
// 	return &state
// }

// func (s *Sandbox) Save(ctx context.Context, path string) error {
// 	for endpointID, id := range s.endpoints {
// 		if err := s.gm.RemoveNetworkInterface(ctx, s.netns, id); err != nil {
// 			return err
// 		}
// 		if err := s.vm.RemoveNIC(ctx, id); err != nil {
// 			return err
// 		}
// 		delete(s.endpoints, endpointID)
// 	}
// 	if err := s.gm.Disconnect(ctx); err != nil {
// 		return err
// 	}
// 	if err := s.vm.Pause(ctx); err != nil {
// 		return err
// 	}
// 	if err := s.vm.Save(ctx, filepath.Join(path, "vmstate")); err != nil {
// 		return err
// 	}

// 	state := sandboxState{
// 		GuestManager: s.gm.State(),
// 		VMOpts:       s.vmOpts,
// 	}
// 	select {
// 	case <-s.waitCh:
// 		state.WaitDone = true
// 		state.WaitErr = s.waitErr.Error()
// 	default:
// 	}
// 	state.PauseCtr = s.pauseCtr.state()
// 	for id, c := range s.ctrs {
// 		state.Ctrs[id] = c.state()
// 	}
// 	if err := statepkg.Write(filepath.Join(path, "state.json"), &state); err != nil {
// 		return err
// 	}

// 	return nil
// }
