package linuxvm

import (
	"context"
	"fmt"
	"path"
	"strings"
	"sync/atomic"

	"github.com/Microsoft/hcsshim/internal/core"
	"github.com/Microsoft/hcsshim/internal/cow"
	"github.com/Microsoft/hcsshim/internal/guestmanager"
	"github.com/Microsoft/hcsshim/internal/guestpath"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/hcsoci"
	"github.com/Microsoft/hcsshim/internal/layers"
	"github.com/Microsoft/hcsshim/internal/ospath"
	"github.com/Microsoft/hcsshim/internal/uvm/scsi"
	"github.com/opencontainers/runtime-spec/specs-go"
	log "github.com/sirupsen/logrus"
)

type guestConfig struct {
	doc    *specs.Spec
	layers *layers.LCOWLayers2
	plan9s []*core.Plan9Config
}

type guestThing struct {
	gm          *guestmanager.LinuxManager
	scsiMounter *scsi.MountManager
	ctrCounter  uint32
	bundleFmt   string
	plan9Config map[string][]*core.Plan9Config
}

func newGuestThing(gm *guestmanager.LinuxManager) *guestThing {
	return &guestThing{
		gm:          gm,
		scsiMounter: scsi.NewMountManager(scsi.NewLinuxGuestManagerBackend(gm), "/run/mounts/scsi/m%d"),
		bundleFmt:   "/run/gcs/c/%d",
	}
}

func newGuestThingWithMountManager(gm *guestmanager.LinuxManager, mountManager *scsi.MountManager) *guestThing {
	return &guestThing{
		gm:          gm,
		scsiMounter: mountManager, // Use the provided MountManager
		bundleFmt:   "/run/gcs/c/%d",
		plan9Config: make(map[string][]*core.Plan9Config),
	}
}

func (gt *guestThing) ctrBundle() string {
	index := atomic.AddUint32(&gt.ctrCounter, 1)
	return fmt.Sprintf(gt.bundleFmt, index)
}

func (gt *guestThing) OpenContainer(ctx context.Context, id string) (_ cow.Container, err error) {
	ctr, err := gt.gm.OpenContainer(ctx, id)
	if err != nil {
		return nil, err
	}
	return ctr, nil
}

func (gt *guestThing) CreateContainer(ctx context.Context, id string, gc *guestConfig) (_ cow.Container, err error) {
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

	for i, plan9Conf := range gc.plan9s {
		uvmPathForShare := path.Join(rootfs, fmt.Sprintf(guestpath.LCOWMountPathPrefixFmt, i))
		uvmPathForFile := uvmPathForShare

		log.Infof("UVMPathForFile: %s", uvmPathForFile)

		if len(plan9Conf.AllowedFiles) > 0 {
			uvmPathForFile = path.Join(uvmPathForShare, plan9Conf.AllowedFiles[0])
		}

		err := gt.gm.MountPlan9Share(ctx, plan9Conf.Name, uvmPathForFile, plan9Conf.ReadOnly)
		if err != nil {
			return nil, err
		}
		log.Infof("Previous Container doc: %+v", doc.OciSpecification.Mounts)
		for idx, mount := range doc.OciSpecification.Mounts {
			log.Infof("harsh-debug: %s ---- %s", mount.Source, plan9Conf.HostPath)
			if mount.Type == hcsoci.MountTypeBind &&
				strings.EqualFold(mount.Source, plan9Conf.HostPath) {
				doc.OciSpecification.Mounts[idx].Source = uvmPathForFile
				gc.plan9s[i].UvmPath = uvmPathForFile
			}
		}
		log.Printf("UVM Path for File is: %s", uvmPathForFile)
	}
	gt.plan9Config[id] = gc.plan9s

	log.Infof("Container doc: %+v", doc.OciSpecification.Mounts)

	ctr, err := gt.gm.CreateContainer(ctx, id, doc)
	if err != nil {
		return nil, err
	}

	return ctr, nil
}

func (gt *guestThing) RemoveContainerResources(ctx context.Context, cid string) (err error) {
	plan9Configs, ok := gt.plan9Config[cid]
	if ok {
		for _, config := range plan9Configs {
			err := gt.gm.UnMountPlan9Share(ctx, config.Name, config.UvmPath)
			if err != nil {
				return fmt.Errorf("failed to unmount plan 9 share %s: %w", config.UvmPath, err)
			}
		}
	}

	return nil
}
