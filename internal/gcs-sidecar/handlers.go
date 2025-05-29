//go:build windows
// +build windows

package bridge

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Microsoft/hcsshim/hcn"
	"github.com/Microsoft/hcsshim/internal/bridgeutils/commonutils"
	"github.com/Microsoft/hcsshim/internal/fsformatter"
	"github.com/Microsoft/hcsshim/internal/gcs/prot"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/oc"
	"github.com/Microsoft/hcsshim/internal/oci"
	"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
	"github.com/Microsoft/hcsshim/internal/windevice"
	"github.com/Microsoft/hcsshim/pkg/cimfs"
	"github.com/pkg/errors"
)

const (
	sandboxStateDirName = "WcSandboxState"
	hivesDirName        = "Hives"
	devPathFormat       = "\\\\.\\PHYSICALDRIVE%d"
)

// - Handler functions handle the incoming message requests. It
// also enforces security policy for confidential cwcow containers.
// - These handler functions may do some additional processing before
// forwarding requests to inbox GCS or send responses back to hcsshim.
// - In case of any error encountered during processing, appropriate error
// messages are returned and responses are sent back to hcsshim from ListenAndServer().
// TODO (kiashok): Verbose logging is for WIP and will be removed eventually.
func (b *Bridge) createContainer(req *request) (err error) {
	ctx, span := oc.StartSpan(req.ctx, "sidecar::createContainer")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	var r prot.ContainerCreate
	var containerConfig json.RawMessage
	r.ContainerConfig.Value = &containerConfig
	if err = commonutils.UnmarshalJSONWithHresult(req.message, &r); err != nil {
		return errors.Wrap(err, "failed to unmarshal createContainer")
	}

	// containerConfig can be of type uvnConfig or hcsschema.HostedSystem
	var (
		uvmConfig          prot.UvmConfig
		hostedSystemConfig hcsschema.HostedSystem
		jobContainerConfig prot.JobContainerConfig
	)
	if err = commonutils.UnmarshalJSONWithHresult(containerConfig, &uvmConfig); err == nil &&
		uvmConfig.SystemType != "" {
		systemType := uvmConfig.SystemType
		timeZoneInformation := uvmConfig.TimeZoneInformation
		log.G(ctx).Tracef("createContainer: uvmConfig: {systemType: %v, timeZoneInformation: %v}}", systemType, timeZoneInformation)
	} else if err = commonutils.UnmarshalJSONWithHresult(containerConfig, &hostedSystemConfig); err == nil &&
		hostedSystemConfig.SchemaVersion != nil && hostedSystemConfig.Container != nil {
		schemaVersion := hostedSystemConfig.SchemaVersion
		container := hostedSystemConfig.Container
		log.G(ctx).Tracef("createContainer: HostedSystemConfig: {schemaVersion: %v, container: %v}}", schemaVersion, container)
	} else if err = json.Unmarshal(containerConfig, &jobContainerConfig); err == nil && jobContainerConfig.Spec != nil {
		// If this request is to create a job container, then we process it in the side-car gcs without
		// forwarding it to the inbox gcs.
		log.G(ctx).Tracef("harshrawat Job Container Config inside is: %+v", jobContainerConfig.Spec)
		if !oci.IsIsolatedJobContainer(jobContainerConfig.Spec) {
			return fmt.Errorf("expected job container configuration")
		}

		container, err := b.hostState.CreateContainer(req.ctx, r.ContainerID, jobContainerConfig.Spec)
		if err != nil {
			return fmt.Errorf("failed to create container: %w", err)
		}

		go func() {
			_ = container.Wait()

			notification := &prot.ContainerNotification{
				RequestBase: prot.RequestBase{
					ContainerID: r.ContainerID,
					ActivityID:  r.ActivityID,
				},
				Operation:  "None",
				Result:     0,
				ResultInfo: prot.AnyInString{Value: ""},
			}
			_ = b.sendNotificationToShim(notification)
		}()

		// Send response back to shim
		return b.sendSuccessMessageToShim(req.ctx, req.activityID, prot.RPCCreate, req.header.ID)
	} else {
		return fmt.Errorf("invalid request to createContainer")
	}

	b.forwardRequestToGcs(req)
	return err
}

func (b *Bridge) startContainer(req *request) (err error) {
	_, span := oc.StartSpan(req.ctx, "sidecar::startContainer")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	var r prot.RequestBase
	if err := commonutils.UnmarshalJSONWithHresult(req.message, &r); err != nil {
		return errors.Wrapf(err, "failed to unmarshal startContainer")
	}

	// Check if the container id is that of a job container. If so then no-op.
	if b.hostState.IsManagedContainer(r.ContainerID) {
		if err := b.hostState.StartContainer(req.ctx, r.ContainerID); err != nil {
			return fmt.Errorf("failed to start container: %w", err)
		}

		log.G(req.ctx).Tracef("Started container: %v", r.ContainerID)
		// Send response back to shim
		return b.sendSuccessMessageToShim(req.ctx, req.activityID, prot.RPCStart, req.header.ID)
	}

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) shutdownGraceful(req *request) (err error) {
	_, span := oc.StartSpan(req.ctx, "sidecar::shutdownGraceful")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	var r prot.RequestBase
	if err := commonutils.UnmarshalJSONWithHresult(req.message, &r); err != nil {
		return errors.Wrap(err, "failed to unmarshal shutdownGraceful")
	}

	// TODO (kiashok/Mahati): Since gcs-sidecar can be used for all types of windows
	// containers, it is important to check if we want to
	// enforce policy or not.

	if b.hostState.IsManagedContainer(r.ContainerID) {
		if err := b.hostState.ShutdownContainer(req.ctx, r.ContainerID); err != nil {
			return fmt.Errorf("failed to shutdown container: %w", err)
		}

		// Send response back to shim
		return b.sendSuccessMessageToShim(req.ctx, req.activityID, prot.RPCShutdownGraceful, req.header.ID)
	}

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) shutdownForced(req *request) (err error) {
	_, span := oc.StartSpan(req.ctx, "sidecar::shutdownForced")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	var r prot.RequestBase
	if err := commonutils.UnmarshalJSONWithHresult(req.message, &r); err != nil {
		return errors.Wrap(err, "failed to unmarshal shutdownForced")
	}

	if b.hostState.IsManagedContainer(r.ContainerID) {
		if err := b.hostState.TerminateContainer(req.ctx, r.ContainerID); err != nil {
			return fmt.Errorf("failed to terminate container: %w", err)
		}

		// Send response back to shim
		return b.sendSuccessMessageToShim(req.ctx, req.activityID, prot.RPCShutdownForced, req.header.ID)
	}

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) executeProcess(req *request) (err error) {
	_, span := oc.StartSpan(req.ctx, "sidecar::executeProcess")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	var r prot.ContainerExecuteProcess
	var processParamSettings json.RawMessage
	r.Settings.ProcessParameters.Value = &processParamSettings
	if err := commonutils.UnmarshalJSONWithHresult(req.message, &r); err != nil {
		return errors.Wrap(err, "failed to unmarshal executeProcess")
	}

	var processParams hcsschema.ProcessParameters
	if err := commonutils.UnmarshalJSONWithHresult(processParamSettings, &processParams); err != nil {
		return errors.Wrap(err, "executeProcess: invalid params type for request")
	}

	if b.hostState.IsManagedContainer(r.ContainerID) {
		process, err := b.hostState.StartProcess(req.ctx, r.ContainerID, &processParams, r.Settings.StdioRelaySettings)
		if err != nil {
			return fmt.Errorf("rpcExecProcess: failed to start process: %w", err)
		}

		resp := &prot.ContainerExecuteProcessResponse{
			ResponseBase: prot.ResponseBase{
				Result:     0,
				ActivityID: r.ActivityID,
			},
			ProcessID: uint32(process.Pid()),
		}
		err = b.sendResponseToShim(req.ctx, prot.RPCExecuteProcess, req.header.ID, resp)
		if err != nil {
			return fmt.Errorf("error sending reply to hcsshim: %w", err)
		}
		return nil
	}

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) waitForProcess(req *request) (err error) {
	_, span := oc.StartSpan(req.ctx, "sidecar::waitForProcess")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	var r prot.ContainerWaitForProcess
	if err := commonutils.UnmarshalJSONWithHresult(req.message, &r); err != nil {
		return errors.Wrap(err, "failed to unmarshal waitForProcess")
	}

	if b.hostState.IsManagedContainer(r.ContainerID) {
		exitCode, err := b.hostState.WaitOnProcess(r.ContainerID, r.ProcessID, r.TimeoutInMs)
		if err != nil {
			return err
		}

		resp := &prot.ContainerWaitForProcessResponse{
			ResponseBase: prot.ResponseBase{
				Result:     0,
				ActivityID: r.ActivityID,
			},
			ExitCode: exitCode,
		}
		err = b.sendResponseToShim(req.ctx, prot.RPCWaitForProcess, req.header.ID, resp)
		if err != nil {
			return fmt.Errorf("error sending reply to hcsshim: %w", err)
		}
		return nil
	}

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) signalProcess(req *request) (err error) {
	_, span := oc.StartSpan(req.ctx, "sidecar::signalProcess")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	var r prot.ContainerSignalProcess
	var rawOpts json.RawMessage
	r.Options = &rawOpts
	if err := commonutils.UnmarshalJSONWithHresult(req.message, &r); err != nil {
		return errors.Wrap(err, "failed to unmarshal signalProcess")
	}

	var wcowOptions guestresource.SignalProcessOptionsWCOW
	if rawOpts != nil {
		if err := commonutils.UnmarshalJSONWithHresult(rawOpts, &wcowOptions); err != nil {
			return errors.Wrap(err, "signalProcess: invalid Options type for request")
		}
	}

	if b.hostState.IsManagedContainer(r.ContainerID) {
		err := b.hostState.SignalContainerProcess(req.ctx, r.ContainerID, r.ProcessID, wcowOptions)
		if err != nil {
			return fmt.Errorf("error signalling process: %w", err)
		}

		// Send response back to shim
		return b.sendSuccessMessageToShim(req.ctx, req.activityID, prot.RPCSignalProcess, req.header.ID)
	}

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) resizeConsole(req *request) (err error) {
	_, span := oc.StartSpan(req.ctx, "sidecar::resizeConsole")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	var r prot.ContainerResizeConsole
	if err := commonutils.UnmarshalJSONWithHresult(req.message, &r); err != nil {
		return fmt.Errorf("failed to unmarshal resizeConsole: %v", req)
	}

	if b.hostState.IsManagedContainer(r.ContainerID) {
		err := b.hostState.ResizeConsole(req.ctx, r.ContainerID, r.ProcessID, r.Width, r.Height)
		if err != nil {
			return fmt.Errorf("error resizing console: %w", err)
		}

		// Send response back to shim
		return b.sendSuccessMessageToShim(req.ctx, req.activityID, prot.RPCResizeConsole, req.header.ID)
	}

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) getProperties(req *request) (err error) {
	_, span := oc.StartSpan(req.ctx, "sidecar::getProperties")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	var getPropReqV2 prot.ContainerGetPropertiesV2
	if err := commonutils.UnmarshalJSONWithHresult(req.message, &getPropReqV2); err != nil {
		return errors.Wrapf(err, "failed to unmarshal getProperties: %v", string(req.message))
	}
	log.G(req.ctx).Tracef("getProperties query: %v", getPropReqV2.Query.PropertyTypes)

	if b.hostState.IsManagedContainer(getPropReqV2.ContainerID) {
		properties, err := b.hostState.GetProperties(req.ctx, getPropReqV2.ContainerID, getPropReqV2.Query.PropertyTypes...)
		if err != nil {
			return err
		}

		if properties == nil {
			properties = &hcsschema.Properties{}
		}

		resp := &prot.ContainerGetPropertiesResponseV2{
			ResponseBase: prot.ResponseBase{
				Result:     0,
				ActivityID: getPropReqV2.ActivityID,
			},
			Properties: prot.ContainerPropertiesV2(*properties),
		}

		err = b.sendResponseToShim(req.ctx, prot.RPCGetProperties, req.header.ID, resp)
		if err != nil {
			return fmt.Errorf("error sending reply to hcsshim: %w", err)
		}
		return nil
	}

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) negotiateProtocol(req *request) (err error) {
	_, span := oc.StartSpan(req.ctx, "sidecar::negotiateProtocol")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	var r prot.NegotiateProtocolRequest
	if err := commonutils.UnmarshalJSONWithHresult(req.message, &r); err != nil {
		return errors.Wrap(err, "failed to unmarshal negotiateProtocol")
	}

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) dumpStacks(req *request) (err error) {
	_, span := oc.StartSpan(req.ctx, "sidecar::dumpStacks")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	var r prot.DumpStacksRequest
	if err := commonutils.UnmarshalJSONWithHresult(req.message, &r); err != nil {
		return errors.Wrap(err, "failed to unmarshal dumpStacks")
	}

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) deleteContainerState(req *request) (err error) {
	_, span := oc.StartSpan(req.ctx, "sidecar::deleteContainerState")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	var r prot.DeleteContainerStateRequest
	if err := commonutils.UnmarshalJSONWithHresult(req.message, &r); err != nil {
		return errors.Wrap(err, "failed to unmarshal deleteContainerState")
	}

	if b.hostState.IsManagedContainer(r.ContainerID) {
		err := b.hostState.RemoveContainerState(r.ContainerID)
		if err != nil {
			return fmt.Errorf("error removing container state: %w", err)
		}

		// Send response back to shim
		return b.sendSuccessMessageToShim(req.ctx, req.activityID, prot.RPCDeleteContainerState, req.header.ID)
	}

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) updateContainer(req *request) (err error) {
	_, span := oc.StartSpan(req.ctx, "sidecar::updateContainer")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	// No callers in the code for rpcUpdateContainer
	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) lifecycleNotification(req *request) (err error) {
	_, span := oc.StartSpan(req.ctx, "sidecar::lifecycleNotification")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	// No callers in the code for rpcLifecycleNotification
	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) modifySettings(req *request) (err error) {
	ctx, span := oc.StartSpan(req.ctx, "sidecar::modifySettings")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	log.G(ctx).Tracef("modifySettings: MsgType: %v, Payload: %v", req.header.Type, string(req.message))
	modifyRequest, err := unmarshalContainerModifySettings(req)
	if err != nil {
		return err
	}
	modifyGuestSettingsRequest := modifyRequest.Request.(*guestrequest.ModificationRequest)
	guestResourceType := modifyGuestSettingsRequest.ResourceType
	guestRequestType := modifyGuestSettingsRequest.RequestType
	log.G(ctx).Tracef("modifySettings: resourceType: %v, requestType: %v", guestResourceType, guestRequestType)

	if guestRequestType == "" {
		guestRequestType = guestrequest.RequestTypeAdd
	}

	containerID := modifyRequest.ContainerID
	if containerID != prot.NullContainerID && b.hostState.IsManagedContainer(containerID) {
		if err = b.hostState.ModifyContainer(req.ctx, containerID, modifyGuestSettingsRequest); err != nil {
			return fmt.Errorf("failed to modify container: %w", err)
		}

		// Send response back to shim
		return b.sendSuccessMessageToShim(req.ctx, req.activityID, prot.RPCModifySettings, req.header.ID)
	}

	switch guestRequestType {
	case guestrequest.RequestTypeAdd:
	case guestrequest.RequestTypeRemove:
	case guestrequest.RequestTypePreAdd:
	case guestrequest.RequestTypeUpdate:
	default:
		return fmt.Errorf("invald guestRequestType %v", guestRequestType)
	}

	if guestResourceType != "" {
		switch guestResourceType {
		case guestresource.ResourceTypeCombinedLayers:
			settings := modifyGuestSettingsRequest.Settings.(*guestresource.WCOWCombinedLayers)
			log.G(ctx).Tracef("WCOWCombinedLayers: {%v}", settings)

		case guestresource.ResourceTypeNetworkNamespace:
			settings := modifyGuestSettingsRequest.Settings.(*hcn.HostComputeNamespace)
			log.G(ctx).Tracef("HostComputeNamespaces { %v}", settings)

		case guestresource.ResourceTypeNetwork:
			settings := modifyGuestSettingsRequest.Settings.(*guestrequest.NetworkModifyRequest)
			log.G(ctx).Tracef("NetworkModifyRequest { %v}", settings)

		case guestresource.ResourceTypeMappedVirtualDisk:
			wcowMappedVirtualDisk := modifyGuestSettingsRequest.Settings.(*guestresource.WCOWMappedVirtualDisk)
			log.G(ctx).Tracef("wcowMappedVirtualDisk { %v}", wcowMappedVirtualDisk)

		case guestresource.ResourceTypeHvSocket:
			hvSocketAddress := modifyGuestSettingsRequest.Settings.(*hcsschema.HvSocketAddress)
			log.G(ctx).Tracef("hvSocketAddress { %v }", hvSocketAddress)

		case guestresource.ResourceTypeMappedDirectory:
			settings := modifyGuestSettingsRequest.Settings.(*hcsschema.MappedDirectory)
			log.G(ctx).Tracef("hcsschema.MappedDirectory { %v }", settings)

		case guestresource.ResourceTypeSecurityPolicy:
			securityPolicyRequest := modifyGuestSettingsRequest.Settings.(*guestresource.WCOWConfidentialOptions)
			log.G(ctx).Tracef("WCOWConfidentialOptions: { %v}", securityPolicyRequest)
			_ = b.hostState.SetWCOWConfidentialUVMOptions(securityPolicyRequest)

			// Send response back to shim
			resp := &prot.ResponseBase{
				Result:     0, // 0 means success
				ActivityID: req.activityID,
			}
			err := b.sendResponseToShim(req.ctx, prot.RPCModifySettings, req.header.ID, resp)
			if err != nil {
				return errors.Wrap(err, "error sending response to hcsshim")
			}
			return nil

		case guestresource.ResourceTypeWCOWBlockCims:
			// This is request to mount the merged cim at given volumeGUID
			wcowBlockCimMounts := modifyGuestSettingsRequest.Settings.(*guestresource.WCOWBlockCIMMounts)
			log.G(ctx).Tracef("WCOWBlockCIMMounts { %v}", wcowBlockCimMounts)

			// The block device takes some time to show up. Wait for a few seconds.
			time.Sleep(2 * time.Second)

			var layerCIMs []*cimfs.BlockCIM
			for _, blockCimDevice := range wcowBlockCimMounts.BlockCIMs {
				// Get the scsi device path for the blockCim lun
				devNumber, err := windevice.GetDeviceNumberFromControllerLUN(
					ctx,
					0, /* controller is always 0 for wcow */
					uint8(blockCimDevice.Lun))
				if err != nil {
					return errors.Wrap(err, "err getting scsiDevPath")
				}
				layerCim := cimfs.BlockCIM{
					Type:      cimfs.BlockCIMTypeDevice,
					BlockPath: fmt.Sprintf(devPathFormat, devNumber),
					CimName:   blockCimDevice.CimName,
				}
				layerCIMs = append(layerCIMs, &layerCim)
			}
			if len(layerCIMs) > 1 {
				// Get the topmost merge CIM and invoke the MountMergedBlockCIMs
				_, err := cimfs.MountMergedBlockCIMs(layerCIMs[0], layerCIMs[1:], wcowBlockCimMounts.MountFlags, wcowBlockCimMounts.VolumeGUID)
				if err != nil {
					return errors.Wrap(err, "error mounting multilayer block cims")
				}
			} else {
				_, err := cimfs.Mount(filepath.Join(layerCIMs[0].BlockPath, layerCIMs[0].CimName), wcowBlockCimMounts.VolumeGUID, wcowBlockCimMounts.MountFlags)
				if err != nil {
					return errors.Wrap(err, "error mounting merged block cims")
				}
			}

			// Send response back to shim
			resp := &prot.ResponseBase{
				Result:     0, // 0 means success
				ActivityID: req.activityID,
			}
			err = b.sendResponseToShim(req.ctx, prot.RPCModifySettings, req.header.ID, resp)
			if err != nil {
				return errors.Wrap(err, "error sending response to hcsshim")
			}
			return nil

		case guestresource.ResourceTypeCWCOWCombinedLayers:
			settings := modifyGuestSettingsRequest.Settings.(*guestresource.CWCOWCombinedLayers)
			containerID := settings.ContainerID
			log.G(ctx).Tracef("CWCOWCombinedLayers:: ContainerID: %v, ContainerRootPath: %v, Layers: %v, ScratchPath: %v",
				containerID, settings.CombinedLayers.ContainerRootPath, settings.CombinedLayers.Layers, settings.CombinedLayers.ScratchPath)

			// TODO: Update modifyCombinedLayers with verified CimFS API

			// The following two folders are expected to be present in the scratch.
			// But since we have just formatted the scratch we would need to
			// create them manually.
			sandboxStateDirectory := filepath.Join(settings.CombinedLayers.ContainerRootPath, sandboxStateDirName)
			err = os.Mkdir(sandboxStateDirectory, 0777)
			if err != nil {
				return errors.Wrap(err, "failed to create sandboxStateDirectory")
			}

			hivesDirectory := filepath.Join(settings.CombinedLayers.ContainerRootPath, hivesDirName)
			err = os.Mkdir(hivesDirectory, 0777)
			if err != nil {
				return errors.Wrap(err, "failed to create hivesDirectory")
			}

			// Reconstruct WCOWCombinedLayers{} req before forwarding to GCS
			// as GCS does not understand ResourceTypeCWCOWCombinedLayers
			modifyGuestSettingsRequest.ResourceType = guestresource.ResourceTypeCombinedLayers
			modifyGuestSettingsRequest.Settings = settings.CombinedLayers
			modifyRequest.Request = modifyGuestSettingsRequest
			buf, err := json.Marshal(modifyRequest)
			if err != nil {
				return errors.Wrap(err, "failed to marshal rpcModifySettings")
			}
			var newRequest request
			newRequest.ctx = req.ctx
			newRequest.header = req.header
			newRequest.header.Size = uint32(len(buf)) + prot.HdrSize
			newRequest.message = buf
			req = &newRequest

		case guestresource.ResourceTypeMappedVirtualDiskForContainerScratch:
			wcowMappedVirtualDisk := modifyGuestSettingsRequest.Settings.(*guestresource.WCOWMappedVirtualDisk)
			log.G(ctx).Tracef("ResourceTypeMappedVirtualDiskForContainerScratch: { %v }", wcowMappedVirtualDisk)

			// 1. TODO (Mahati): Need to enforce policy before calling into fsFormatter
			// 2. Call fsFormatter to format the scratch disk.
			// This will return the volume path of the mounted scratch.
			// Scratch disk should be >= 30 GB for refs formatter to work.

			// fsFormatter understands only virtualDevObjectPathFormat. Therefore fetch the
			// disk number for the corresponding lun
			var devNumber uint32
			// It could take a few seconds for the attached scsi disk
			// to show up inside the UVM. Therefore adding retry logic
			// with delay here.
			for try := 0; try < 5; try++ {
				time.Sleep(1 * time.Second)
				devNumber, err = windevice.GetDeviceNumberFromControllerLUN(req.ctx,
					0, /* Only one controller allowed in wcow hyperv */
					uint8(wcowMappedVirtualDisk.Lun))
				if err != nil {
					if try == 4 {
						// bail out
						return errors.Wrapf(err, "error getting diskNumber for LUN %d", wcowMappedVirtualDisk.Lun)
					}
					continue
				} else {
					log.G(ctx).Tracef("DiskNumber of lun %d is:  %d", wcowMappedVirtualDisk.Lun, devNumber)
					break
				}
			}
			diskPath := fmt.Sprintf(fsformatter.VirtualDevObjectPathFormat, devNumber)
			log.G(ctx).Tracef("diskPath: %v, diskNumber: %v ", diskPath, devNumber)
			mountedVolumePath, err := fsformatter.InvokeFsFormatter(req.ctx, diskPath)
			if err != nil {
				return errors.Wrap(err, "failed to invoke refsFormatter")
			}
			log.G(ctx).Tracef("mountedVolumePath returned from InvokeFsFormatter: %v", mountedVolumePath)

			// Forward the req as is to inbox gcs and let it retreive the volume.
			// While forwarding request to inbox gcs, make sure to replace the
			// resourceType to ResourceTypeMappedVirtualDisk that inbox GCS
			// understands.
			modifyGuestSettingsRequest.ResourceType = guestresource.ResourceTypeMappedVirtualDisk
			modifyRequest.Request = modifyGuestSettingsRequest
			buf, err := json.Marshal(modifyRequest)
			if err != nil {
				return errors.Wrap(err, "failed to marshal WCOWMappedVirtualDisk")
			}
			var newRequest request
			newRequest.ctx = req.ctx
			newRequest.header = req.header
			newRequest.header.Size = uint32(len(buf)) + prot.HdrSize
			newRequest.message = buf
			req = &newRequest

		default:
			// Invalid request
			return fmt.Errorf("invald modifySettingsRequest: %v", guestResourceType)
		}
	}

	b.forwardRequestToGcs(req)
	return nil
}
