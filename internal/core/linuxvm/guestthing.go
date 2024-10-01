package linuxvm

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/Microsoft/hcsshim/internal/cow"
	"github.com/Microsoft/hcsshim/internal/guestmanager"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/layers"
	"github.com/Microsoft/hcsshim/internal/ospath"
	"github.com/Microsoft/hcsshim/internal/uvm/scsi"
	"github.com/opencontainers/runtime-spec/specs-go"
)

type guestConfig struct {
	doc    *specs.Spec
	layers *layers.LCOWLayers2
}

type guestThing struct {
	gm          *guestmanager.LinuxManager
	scsiMounter *scsi.MountManager
	ctrCounter  uint32
	bundleFmt   string
}

func newGuestThing(gm *guestmanager.LinuxManager) *guestThing {
	return &guestThing{
		gm:          gm,
		scsiMounter: scsi.NewMountManager(scsi.NewLinuxGuestManagerBackend(gm), "/run/mounts/scsi/m%d"),
		bundleFmt:   "/run/gcs/c/%d",
	}
}

func (gt *guestThing) ctrBundle() string {
	index := atomic.AddUint32(&gt.ctrCounter, 1)
	return fmt.Sprintf(gt.bundleFmt, index)
}

func (gt *guestThing) DoTheThing(ctx context.Context, id string, gc *guestConfig) (_ cow.Container, err error) {
	var scratchMount string
	switch scratch := gc.layers.Scratch.(type) {
	case *layers.LCOWLayerSCSI:
		config := &scsi.MountConfig{}
		scratchMount, err = gt.scsiMounter.Mount(ctx, scratch.Controller, scratch.LUN, config)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported layer type: %T", scratch)
	}

	var roPaths []string
	for _, layer := range gc.layers.Layers {
		switch layer := layer.(type) {
		case *layers.LCOWLayerSCSI:
			config := &scsi.MountConfig{
				ReadOnly: true,
				Options:  []string{"ro"},
			}
			layerMount, err := gt.scsiMounter.Mount(ctx, layer.Controller, layer.LUN, config)
			if err != nil {
				return nil, err
			}
			roPaths = append(roPaths, layerMount)
		default:
			return nil, fmt.Errorf("unsupported layer type: %T", layer)
		}
	}

	bundle := gt.ctrBundle()
	rootfs := ospath.Join("linux", bundle, "rootfs")
	if err := gt.gm.MountOverlayFS(ctx, id, rootfs, scratchMount, roPaths); err != nil {
		return nil, err
	}
	if gc.doc.Root == nil {
		gc.doc.Root = &specs.Root{Path: rootfs}
	} else {
		gc.doc.Root.Path = rootfs
	}
	doc := &linuxHostedSystem{
		SchemaVersion:    &hcsschema.Version{Major: 2, Minor: 1},
		OciBundlePath:    bundle,
		OciSpecification: gc.doc,
	}

	ctr, err := gt.gm.CreateContainer(ctx, id, doc)
	if err != nil {
		return nil, err
	}

	return ctr, nil
}
