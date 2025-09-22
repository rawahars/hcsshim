package guestmanager

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/Microsoft/hcsshim/internal/cow"
	"github.com/Microsoft/hcsshim/internal/gcs"
	"github.com/Microsoft/hcsshim/internal/hcs/schema1"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
	statepkg "github.com/Microsoft/hcsshim/internal/state"
	"golang.org/x/sync/errgroup"
)

type LinuxManager struct {
	entropyListener, logListener, gcsListener net.Listener
	listenCreator                             func(uint32) (net.Listener, error)

	gc        *gcs.GuestConnection
	guestCaps *schema1.GuestDefinedCapabilities
	protocol  uint32

	mu       sync.Mutex
	nextPort uint32
	procs    []*statepkg.Process
}

func NewLinuxManager(listenCreator func(uint32) (net.Listener, error)) (*LinuxManager, error) {
	entropyListener, err := listenCreator(1)
	if err != nil {
		return nil, err
	}
	logListener, err := listenCreator(109)
	if err != nil {
		return nil, err
	}
	gcsListener, err := listenCreator(gcs.LinuxGcsVsockPort)
	if err != nil {
		return nil, err
	}
	return &LinuxManager{
		entropyListener: entropyListener,
		logListener:     logListener,
		gcsListener:     gcsListener,
		listenCreator:   listenCreator,
		nextPort:        gcs.FirstIoChannelVsockPort,
	}, nil
}

func NewLinuxManagerFromState(listenCreator func(uint32) (net.Listener, error), state *statepkg.GCState) (*LinuxManager, error) {
	entropyListener, err := listenCreator(1)
	if err != nil {
		return nil, err
	}
	logListener, err := listenCreator(109)
	if err != nil {
		return nil, err
	}
	gcsListener, err := listenCreator(gcs.LinuxGcsVsockPort)
	if err != nil {
		return nil, err
	}
	return &LinuxManager{
		entropyListener: entropyListener,
		logListener:     logListener,
		gcsListener:     gcsListener,
		listenCreator:   listenCreator,
		nextPort:        state.NextPort,
		procs:           state.Processes,
	}, nil
}

func (gm *LinuxManager) State() *statepkg.GCState {
	return gm.gc.State()
}

func (gm *LinuxManager) Close() (retErr error) {
	close := func(c io.Closer) {
		if c != nil {
			if err := c.Close(); err != nil && retErr == nil {
				retErr = err
			}
		}
	}
	close(gm.entropyListener)
	close(gm.logListener)
	close(gm.gcsListener)
	close(gm.gc)
	return
}

func (gm *LinuxManager) Start(ctx context.Context, freshStart bool) error {
	var g errgroup.Group

	if freshStart {
		g.Go(func() error {
			if err := func() error {
				c, err := gm.entropyListener.Accept()
				if err != nil {
					return err
				}
				defer c.Close()
				if err := gm.entropyListener.Close(); err != nil {
					return err
				}
				if _, err := io.CopyN(c, rand.Reader, 512); err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return fmt.Errorf("entropy init: %w", err)
			}
			return nil
		})
	}
	// g.Go(func() error {
	// 	if err := func() error {
	// 		_, err := gm.logListener.Accept()
	// 		if err != nil {
	// 			return err
	// 		}
	// 		if err := gm.logListener.Close(); err != nil {
	// 			return err
	// 		}
	// 		return nil
	// 	}(); err != nil {
	// 		return fmt.Errorf("log init: %w", err)
	// 	}
	// 	return nil
	// })
	g.Go(func() error {
		if err := func() (err error) {
			gm.gc, gm.guestCaps, gm.protocol, err = connectGCS(ctx, gm.gcsListener, gm.listenCreator, gm.nextPort, gm.procs)
			if err != nil {
				return err
			}
			return nil
		}(); err != nil {
			return fmt.Errorf("gcs init: %w", err)
		}
		return nil
	})

	ch := make(chan error)
	go func() {
		ch <- g.Wait()
	}()
	select {
	case err := <-ch:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func connectGCS(ctx context.Context, l net.Listener, listenCreator func(uint32) (net.Listener, error), nextPort uint32, procs []*statepkg.Process) (_ *gcs.GuestConnection, _ *schema1.GuestDefinedCapabilities, _ uint32, err error) {
	c, err := l.Accept()
	if err != nil {
		return nil, nil, 0, err
	}
	defer func() {
		if err != nil {
			c.Close()
		}
	}()
	if err := l.Close(); err != nil {
		return nil, nil, 0, err
	}
	conn, ok := c.(gcs.Conn)
	if !ok {
		return nil, nil, 0, fmt.Errorf("conn does not implement gcs.Conn")
	}
	gcc := &gcs.GuestConnectionConfig{
		Conn:      conn,
		IoListen:  listenCreator,
		Log:       log.L,
		NextPort:  nextPort,
		Processes: procs,
	}
	gc, err := gcc.Connect(ctx, true)
	if err != nil {
		return nil, nil, 0, err
	}
	return gc, gc.Capabilities(), gc.Protocol(), nil
}

type InterfaceConfig struct {
	MACAddress      string
	IPAddress       string
	PrefixLength    uint8
	GatewayAddress  string
	DNSSuffix       string
	DNSServerList   string
	EnableLowMetric bool
	EncapOverhead   uint16
}

func (gm *LinuxManager) AddNetworkInterface(ctx context.Context, nsID, ifaceID string, config *InterfaceConfig) error {
	req := guestrequest.ModificationRequest{
		ResourceType: guestresource.ResourceTypeNetwork,
		RequestType:  guestrequest.RequestTypeAdd,
		Settings: &guestresource.LCOWNetworkAdapter{
			NamespaceID:     nsID,
			ID:              ifaceID,
			MacAddress:      config.MACAddress,
			IPAddress:       config.IPAddress,
			PrefixLength:    config.PrefixLength,
			GatewayAddress:  config.GatewayAddress,
			DNSSuffix:       config.DNSSuffix,
			DNSServerList:   config.DNSServerList,
			EnableLowMetric: config.EnableLowMetric,
			EncapOverhead:   config.EncapOverhead,
		},
	}
	if err := gm.gc.Modify(ctx, req); err != nil {
		return err
	}
	return nil
}

func (gm *LinuxManager) RemoveNetworkInterface(ctx context.Context, nsID, ifaceID string) error {
	req := guestrequest.ModificationRequest{
		ResourceType: guestresource.ResourceTypeNetwork,
		RequestType:  guestrequest.RequestTypeRemove,
		Settings: &guestresource.LCOWNetworkAdapter{
			NamespaceID: nsID,
			ID:          ifaceID,
		},
	}
	if err := gm.gc.Modify(ctx, req); err != nil {
		return err
	}
	return nil
}

func (gm *LinuxManager) CreateContainer(ctx context.Context, id string, config any) (cow.Container, error) {
	return gm.gc.CreateContainer(ctx, id, config)
}

func (gm *LinuxManager) OpenContainer(ctx context.Context, id string) (cow.Container, error) {
	return gm.gc.OpenContainer(ctx, id)
}

func (gm *LinuxManager) OpenProcess2(ctx context.Context, pid uint32) (cow.Process, error) {
	panic("not implemented")
}

type SCSIMountOptions struct {
	Partition        uint64
	ReadOnly         bool
	Encrypted        bool
	Options          []string
	EnsureFilesystem bool
	Filesystem       string
}

func (gm *LinuxManager) MountSCSI(ctx context.Context, controller, lun uint8, path string, options *SCSIMountOptions) error {
	req := guestrequest.ModificationRequest{
		ResourceType: guestresource.ResourceTypeMappedVirtualDisk,
		RequestType:  guestrequest.RequestTypeAdd,
		Settings: guestresource.LCOWMappedVirtualDisk{
			MountPath:        path,
			Controller:       uint8(controller),
			Lun:              uint8(lun),
			Partition:        options.Partition,
			ReadOnly:         options.ReadOnly,
			Encrypted:        options.Encrypted,
			Options:          options.Options,
			EnsureFilesystem: options.EnsureFilesystem,
			Filesystem:       options.Filesystem,
		},
	}
	if err := gm.gc.Modify(ctx, req); err != nil {
		return err
	}
	return nil
}

func (gm *LinuxManager) UnmountSCSI(ctx context.Context, controller, lun uint8, path string, partition uint64) error {
	req := guestrequest.ModificationRequest{
		ResourceType: guestresource.ResourceTypeMappedVirtualDisk,
		RequestType:  guestrequest.RequestTypeRemove,
		Settings: guestresource.LCOWMappedVirtualDisk{
			MountPath:  path,
			Controller: controller,
			Lun:        lun,
			Partition:  partition,
		},
	}
	if err := gm.gc.Modify(ctx, req); err != nil {
		return err
	}
	return nil
}

func (gm *LinuxManager) UnplugSCSI(ctx context.Context, controller, lun uint8) error {
	req := guestrequest.ModificationRequest{
		ResourceType: guestresource.ResourceTypeSCSIDevice,
		RequestType:  guestrequest.RequestTypeRemove,
		Settings: guestresource.SCSIDevice{
			Controller: controller,
			Lun:        lun,
		},
	}
	if err := gm.gc.Modify(ctx, req); err != nil {
		return err
	}
	return nil
}

func (gm *LinuxManager) MountOverlayFS(ctx context.Context, cid string, path, scratch string, lower []string) error {
	var layers []hcsschema.Layer
	for _, l := range lower {
		layers = append(layers, hcsschema.Layer{Path: l})
	}
	req := guestrequest.ModificationRequest{
		ResourceType: guestresource.ResourceTypeCombinedLayers,
		RequestType:  guestrequest.RequestTypeAdd,
		Settings: guestresource.LCOWCombinedLayers{
			ContainerID:       cid,
			ContainerRootPath: path,
			Layers:            layers,
			ScratchPath:       scratch,
		},
	}
	if err := gm.gc.Modify(ctx, req); err != nil {
		return err
	}
	return nil
}

func (gm *LinuxManager) MountPlan9Share(ctx context.Context, name string, uvmPath string, readOnly bool) error {
	guestRequest := &guestrequest.ModificationRequest{
		ResourceType: guestresource.ResourceTypeMappedDirectory,
		RequestType:  guestrequest.RequestTypeAdd,
		Settings: guestresource.LCOWMappedDirectory{
			MountPath: uvmPath,
			ShareName: name,
			Port:      564,
			ReadOnly:  readOnly,
		},
	}

	if err := gm.gc.Modify(ctx, guestRequest); err != nil {
		return err
	}
	return nil
}

func (gm *LinuxManager) UnMountPlan9Share(ctx context.Context, name string, uvmPath string) error {
	guestRequest := &guestrequest.ModificationRequest{
		ResourceType: guestresource.ResourceTypeMappedDirectory,
		RequestType:  guestrequest.RequestTypeRemove,
		Settings: guestresource.LCOWMappedDirectory{
			MountPath: uvmPath,
			ShareName: name,
			Port:      564,
		},
	}

	if err := gm.gc.Modify(ctx, guestRequest); err != nil {
		return err
	}
	return nil
}

func (gm *LinuxManager) CreateProcess(ctx context.Context, config interface{}) (cow.Process, error) {
	return gm.gc.CreateProcess(ctx, config)
}

func (gm *LinuxManager) OpenProcess(ctx context.Context, cid string, pid uint32) (cow.Process, error) {
	return gm.gc.OpenProcess(ctx, cid, pid)
}

func (gm *LinuxManager) OS() string {
	return "linux"
}

func (gm *LinuxManager) IsOCI() bool {
	return false
}

func (gm *LinuxManager) Disconnect(ctx context.Context) error {
	return gm.gc.Close()
}
