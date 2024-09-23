package layers

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd/api/types"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/mount"
)

// ValidateRootfsAndLayers checks to ensure we have appropriate information
// for setting up the container's root filesystem. It ensures the following:
// - One and only one of Rootfs or LayerFolders can be provided.
// - If LayerFolders are provided, there are at least two entries.
// - If Rootfs is provided, there is a single entry and it does not have a Target set.
func ValidateRootfsAndLayers(rootfs []*types.Mount, layerFolders []string) error {
	if len(rootfs) > 0 && len(layerFolders) > 0 {
		return fmt.Errorf("cannot pass both a rootfs mount and Windows.LayerFolders: %w", errdefs.ErrFailedPrecondition)
	}
	if len(rootfs) == 0 && len(layerFolders) == 0 {
		return fmt.Errorf("must pass either a rootfs mount or Windows.LayerFolders: %w", errdefs.ErrFailedPrecondition)
	}
	if len(rootfs) > 0 {
		// We have a rootfs.

		if len(rootfs) > 1 {
			return fmt.Errorf("expected a single rootfs mount: %w", errdefs.ErrFailedPrecondition)
		}
		if rootfs[0].Target != "" {
			return fmt.Errorf("rootfs mount is missing Target path: %w", errdefs.ErrFailedPrecondition)
		}
	} else {
		// We have layerFolders.

		if len(layerFolders) < 2 {
			return fmt.Errorf("must pass at least two Windows.LayerFolders: %w", errdefs.ErrFailedPrecondition)
		}
	}

	return nil
}

// ParseLegacyRootfsMount parses the rootfs mount format that we have traditionally
// used for both Linux and Windows containers.
// The mount format consists of:
//   - The scratch folder path in m.Source, which contains sandbox.vhdx.
//   - A mount option in the form parentLayerPaths=<JSON>, where JSON is an array of
//     string paths to read-only layer directories. The exact contents of these layer
//     directories are intepreteted differently for Linux and Windows containers.
func ParseLegacyRootfsMount(m *types.Mount) (string, []string, error) {
	// parentLayerPaths are passed in layerN, layerN-1, ..., layer 0
	//
	// The OCI spec expects:
	//   layerN, layerN-1, ..., layer0, scratch
	var parentLayerPaths []string
	for _, option := range m.Options {
		if strings.HasPrefix(option, mount.ParentLayerPathsFlag) {
			err := json.Unmarshal([]byte(option[len(mount.ParentLayerPathsFlag):]), &parentLayerPaths)
			if err != nil {
				return "", nil, fmt.Errorf("unmarshal parent layer paths from mount: %v: %w", err, errdefs.ErrFailedPrecondition)
			}
			// Would perhaps be worthwhile to check for unrecognized options and return an error,
			// but since this is a legacy layer mount we don't do that to avoid breaking anyone.
			break
		}
	}
	return m.Source, parentLayerPaths, nil
}

func GetLCOWLayers2(l *LCOWLayers) *LCOWLayers2 {
	l2 := &LCOWLayers2{Scratch: &LCOWLayerVHD{VHDPath: l.ScratchVHDPath}}
	for _, l := range l.Layers {
		l2.Layers = append(l2.Layers, &LCOWLayerVHD{VHDPath: l.VHDPath})
	}
	return l2
}

// getLCOWLayers returns a LCOWLayers describing the rootfs that should be set up
// for an LCOW container. It takes as input the set of rootfs mounts and the layer folders
// from the OCI spec, it is assumed that these were previously checked with validateRootfsAndLayers
// such that only one of them is populated.
func GetLCOWLayers(rootfs []*types.Mount, layerFolders []string) (*LCOWLayers, error) {
	legacyLayer := func(scratchLayer string, parentLayers []string) *LCOWLayers {
		// Each read-only layer should have a layer.vhd, and the scratch layer should have a sandbox.vhdx.
		roLayers := make([]*LCOWLayer, 0, len(parentLayers))
		for _, parentLayer := range parentLayers {
			roLayers = append(
				roLayers,
				&LCOWLayer{
					VHDPath: filepath.Join(parentLayer, "layer.vhd"),
				},
			)
		}
		return &LCOWLayers{
			Layers:         roLayers,
			ScratchVHDPath: filepath.Join(scratchLayer, "sandbox.vhdx"),
		}
	}
	// Due to previous validation, we know that for a Linux container we either have LayerFolders, or
	// a single rootfs mount.
	if len(layerFolders) > 0 {
		return legacyLayer(layerFolders[len(layerFolders)-1], layerFolders[:len(layerFolders)-1]), nil
	}
	m := rootfs[0]
	switch m.Type {
	case "lcow-layer":
		scratchLayer, parentLayers, err := ParseLegacyRootfsMount(rootfs[0])
		if err != nil {
			return nil, err
		}
		return legacyLayer(scratchLayer, parentLayers), nil
	case "lcow-partitioned-layer":
		var (
			scratchPath string
			layerData   []struct {
				Path      string
				Partition uint64
			}
		)
		for _, opt := range m.Options {
			if optPrefix := "scratch="; strings.HasPrefix(opt, optPrefix) {
				scratchPath = strings.TrimPrefix(opt, optPrefix)
			} else if optPrefix := "parent-partitioned-layers="; strings.HasPrefix(opt, optPrefix) {
				layerJSON := strings.TrimPrefix(opt, optPrefix)
				if err := json.Unmarshal([]byte(layerJSON), &layerData); err != nil {
					return nil, err
				}
			} else {
				return nil, fmt.Errorf("unrecognized %s mount option: %s", m.Type, opt)
			}
		}
		roLayers := make([]*LCOWLayer, 0, len(layerData))
		for _, layer := range layerData {
			roLayers = append(
				roLayers,
				&LCOWLayer{
					VHDPath:   layer.Path,
					Partition: layer.Partition,
				},
			)
		}
		return &LCOWLayers{Layers: roLayers, ScratchVHDPath: scratchPath}, nil
	default:
		return nil, fmt.Errorf("unrecognized rootfs mount type: %s", m.Type)
	}
}
