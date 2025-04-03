package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/Microsoft/hcsshim/hcn"
	"github.com/Microsoft/hcsshim/internal/guest/commonutils"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
	windowssecuritypolicy "github.com/Microsoft/hcsshim/pkg/securitypolicy"
	"github.com/pkg/errors"
)

func modifyCombinedLayers(
	ctx context.Context,
	containerID string,
	rt guestrequest.RequestType,
	cl guestresource.WCOWCombinedLayers,
	securityPolicy windowssecuritypolicy.SecurityPolicyEnforcer,
) (err error) {
	switch rt {
	case guestrequest.RequestTypeAdd:
		layerPaths := make([]string, len(cl.Layers))
		for i, layer := range cl.Layers {
			layerPaths[i] = layer.Path
			//TODO: Remove this when there is verified Cimfs API. This only here to mock
			// mount device
			log.Printf("enforcing mount_device in combinedlayers: %v, %v", layer.Path, layer.Id)
			securityPolicy.EnforceDeviceMountPolicy(ctx, layer.Path, layer.Id)
		}
		log.Printf("enforcing mount_overlay in combinedlayers")
		return securityPolicy.EnforceOverlayMountPolicy(ctx, containerID, layerPaths, cl.ContainerRootPath)
	case guestrequest.RequestTypeRemove:
		return securityPolicy.EnforceOverlayUnmountPolicy(ctx, cl.ContainerRootPath)
	default:
		return newInvalidRequestTypeError(rt)
	}
}

func newInvalidRequestTypeError(rt guestrequest.RequestType) error {
	return errors.Errorf("the RequestType %q is not supported", rt)
}

func modifyMappedVirtualDisk(
	ctx context.Context,
	rt guestrequest.RequestType,
	mvd *guestresource.WCOWMappedVirtualDisk,
	securityPolicy windowssecuritypolicy.SecurityPolicyEnforcer,
) (err error) {
	switch rt {
	case guestrequest.RequestTypeAdd:
		// TODO: Modify and update this with verified Cims API
		return securityPolicy.EnforceDeviceMountPolicy(ctx, mvd.ContainerPath, "hash")
	case guestrequest.RequestTypeRemove:
		// TODO: Modify and update this with verified Cims API
		return securityPolicy.EnforceDeviceUnmountPolicy(ctx, mvd.ContainerPath)
	default:
		return newInvalidRequestTypeError(rt)
	}
}

func unmarshalContainerModifySettings(req *request) (*containerModifySettings, error) {
	var r containerModifySettings
	var requestRawSettings json.RawMessage
	r.Request = &requestRawSettings
	if err := commonutils.UnmarshalJSONWithHresult(req.message, &r); err != nil {
		return nil, fmt.Errorf("failed to unmarshal rpcModifySettings: %v", req)
	}

	var modifyGuestSettingsRequest guestrequest.ModificationRequest
	var rawGuestRequest json.RawMessage
	modifyGuestSettingsRequest.Settings = &rawGuestRequest
	if err := commonutils.UnmarshalJSONWithHresult(requestRawSettings, &modifyGuestSettingsRequest); err != nil {
		log.Printf("invalid rpcModifySettings ModificationRequest request %v", r)
		return nil, fmt.Errorf("invalid rpcModifySettings ModificationRequest request %v", r)
	}
	log.Printf("rpcModifySettings: ModificationRequest %v\n", modifyGuestSettingsRequest)

	if modifyGuestSettingsRequest.RequestType == "" {
		modifyGuestSettingsRequest.RequestType = guestrequest.RequestTypeAdd
	}

	switch modifyGuestSettingsRequest.ResourceType {
	case guestresource.ResourceTypeCWCOWCombinedLayers:

		settings := &guestresource.CWCOWCombinedLayers{}
		if err := commonutils.UnmarshalJSONWithHresult(rawGuestRequest, settings); err != nil {
			log.Printf("invalid ResourceTypeCombinedLayers request %v", r)
			return nil, fmt.Errorf("invalid ResourceTypeCombinedLayers request %v", r)
		}
		modifyGuestSettingsRequest.Settings = settings

	case guestresource.ResourceTypeCombinedLayers:
		settings := &guestresource.WCOWCombinedLayers{}
		if err := commonutils.UnmarshalJSONWithHresult(rawGuestRequest, settings); err != nil {
			log.Printf("invalid ResourceTypeCombinedLayers request %v", r)
			return nil, fmt.Errorf("invalid ResourceTypeCombinedLayers request %v", r)
		}
		modifyGuestSettingsRequest.Settings = settings

	case guestresource.ResourceTypeNetworkNamespace:
		settings := &hcn.HostComputeNamespace{}
		if err := commonutils.UnmarshalJSONWithHresult(rawGuestRequest, settings); err != nil {
			log.Printf("invalid ResourceTypeNetworkNamespace request %v", r)
			return nil, fmt.Errorf("invalid ResourceTypeNetworkNamespace request %v", r)
		}
		modifyGuestSettingsRequest.Settings = settings

	case guestresource.ResourceTypeNetwork:
		// following valid only for osversion.Build() >= osversion.RS5
		// since Cwcow is available only for latest versions this is ok
		// TODO: Check if osversion >= rs5 else error out
		settings := &guestrequest.NetworkModifyRequest{}
		if err := commonutils.UnmarshalJSONWithHresult(rawGuestRequest, settings); err != nil {
			log.Printf("invalid ResourceTypeNetwork request %v", r)
			return nil, fmt.Errorf("invalid ResourceTypeNetwork request %v", r)
		}
		modifyGuestSettingsRequest.Settings = settings

	case guestresource.ResourceTypeMappedVirtualDisk:
		wcowMappedVirtualDisk := &guestresource.WCOWMappedVirtualDisk{}
		if err := commonutils.UnmarshalJSONWithHresult(rawGuestRequest, wcowMappedVirtualDisk); err != nil {
			log.Printf("invalid ResourceTypeMappedVirtualDisk request %v", r)
			return nil, fmt.Errorf("invalid ResourceTypeMappedVirtualDisk request %v", r)
		}
		modifyGuestSettingsRequest.Settings = wcowMappedVirtualDisk
		log.Printf(", wcowMappedVirtualDisk { %v} \n", wcowMappedVirtualDisk)

	case guestresource.ResourceTypeHvSocket:
		hvSocketAddress := &hcsschema.HvSocketAddress{}
		if err := commonutils.UnmarshalJSONWithHresult(rawGuestRequest, hvSocketAddress); err != nil {
			log.Printf("invalid ResourceTypeHvSocket request %v", r)
			return nil, fmt.Errorf("invalid ResourceTypeHvSocket request %v", r)
		}
		modifyGuestSettingsRequest.Settings = hvSocketAddress

	case guestresource.ResourceTypeMappedDirectory:
		settings := &hcsschema.MappedDirectory{}
		if err := commonutils.UnmarshalJSONWithHresult(rawGuestRequest, settings); err != nil {
			log.Printf("invalid ResourceTypeMappedDirectory request %v", r)
			return nil, fmt.Errorf("invalid ResourceTypeMappedDirectory request %v", r)
		}
		modifyGuestSettingsRequest.Settings = settings

	case guestresource.ResourceTypeSecurityPolicy:
		securityPolicyRequest := &guestresource.WCOWConfidentialOptions{}
		if err := commonutils.UnmarshalJSONWithHresult(rawGuestRequest, securityPolicyRequest); err != nil {
			log.Printf("invalid ResourceTypeSecurityPolicy request %v", r)
			return nil, fmt.Errorf("invalid ResourceTypeSecurityPolicy request %v", r)
		}
		modifyGuestSettingsRequest.Settings = securityPolicyRequest

	case guestresource.ResourceTypeMappedVirtualDiskForContainerScratch:
		wcowMappedVirtualDisk := &guestresource.WCOWMappedVirtualDisk{}
		if err := commonutils.UnmarshalJSONWithHresult(rawGuestRequest, wcowMappedVirtualDisk); err != nil {
			log.Printf("invalid ResourceTypeMappedVirtualDisk request %v", r)
			return nil, fmt.Errorf("invalid ResourceTypeMappedVirtualDisk request %v", r)
		}

	case guestresource.ResourceTypeWCOWBlockCims:
		wcowBlockCimMounts := &guestresource.WCOWBlockCIMMounts{}
		if err := commonutils.UnmarshalJSONWithHresult(rawGuestRequest, wcowBlockCimMounts); err != nil {
			log.Printf("invalid ResourceTypeWCOWBlockCims request %v", r)
			return nil, fmt.Errorf("invalid ResourceTypeWCOWBlockCims request %v", r)
		}

	default:
		// Invalid request
		log.Printf("\n Invald modifySettingsRequest: %v", modifyGuestSettingsRequest.ResourceType)
		return nil, fmt.Errorf("invald modifySettingsRequest: %v", modifyGuestSettingsRequest.ResourceType)
	}
	r.Request = &modifyGuestSettingsRequest
	return &r, nil
}
