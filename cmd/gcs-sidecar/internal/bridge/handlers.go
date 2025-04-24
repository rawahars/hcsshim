//go:build windows
// +build windows

package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Microsoft/hcsshim/internal/gcs"
	"github.com/Microsoft/hcsshim/internal/oci"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/Microsoft/hcsshim/hcn"
	"github.com/Microsoft/hcsshim/internal/fsformatter"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
	"github.com/Microsoft/hcsshim/internal/windevice"
	"github.com/Microsoft/hcsshim/pkg/cimfs"
	"github.com/pkg/errors"
)

const (
	sandboxStateDirName = "WcSandboxState"
	hivesDirName        = "Hives"
)

// - Current intent of these handler functions is to call the security policy
// enforcement code as needed.
// - These handler functions forward the message to inbox GCS or sends response
// back to hcsshim in cases where we do not need to forward message to
// inbox GCS for further processing.
// For example: ResourceTypeSecurityPolicy is something only the gcs-sidecar
// understands and need not be forwarded to inbox gcs.
// - In case of any error encountered during processing, appropriate error
// messages are returned and responses are sent back to hcsshim from caller, ListerAndServer().
func (b *Bridge) createContainer(req *request) error {
	var err error = nil
	var r containerCreate
	var containerConfig json.RawMessage

	r.ContainerConfig.Value = &containerConfig
	if err = json.Unmarshal(req.message, &r); err != nil {
		log.Printf("failed to unmarshal rpcCreate: %v", req)
		return fmt.Errorf("failed to unmarshal rpcCreate: %v", req)
	}

	// containerCreate.ContainerConfig can be of type uvnConfig or hcsschema.HostedSystem
	var uvmConfig uvmConfig
	var hostedSystemConfig hcsschema.HostedSystem
	var jobContainerConfig gcs.JobContainerConfig
	if err = json.Unmarshal(containerConfig, &uvmConfig); err == nil {
		systemType := uvmConfig.SystemType
		timeZoneInformation := uvmConfig.TimeZoneInformation
		log.Printf("rpcCreate: \n ContainerCreate{ requestBase: %v, uvmConfig: {systemType: %v, timeZoneInformation: %v}}", r.requestBase, systemType, timeZoneInformation)
	} else if err = json.Unmarshal(containerConfig, &hostedSystemConfig); err == nil {
		schemaVersion := hostedSystemConfig.SchemaVersion
		container := hostedSystemConfig.Container
		log.Printf("rpcCreate: \n ContainerCreate{ requestBase: %v, ContainerConfig: {schemaVersion: %v, container: %v}}", r.requestBase, schemaVersion, container)
	} else {
		log.Printf("createContainer: invalid containerConfig type. Request: %v", req)
		return fmt.Errorf("createContainer: invalid containerConfig type. Request: %v", r)
	}

	if err = json.Unmarshal(containerConfig, &jobContainerConfig); err == nil && jobContainerConfig.Spec != nil {
		// If this request is to create a job container, then we process it in the side-car gcs without
		// forwarding it to the inbox gcs.
		log.Printf("harshrawat Job Container Config inside is: %+v\n", jobContainerConfig.Spec)
		if !oci.IsIsolatedJobContainer(jobContainerConfig.Spec) {
			return fmt.Errorf("expected job container configuration")
		}

		container, err := b.hostState.CreateContainer(context.Background(), r.ContainerID, jobContainerConfig.Spec)
		if err != nil {
			return fmt.Errorf("failed to create container: %w", err)
		}

		go func() {
			_ = container.Wait()

			log.Printf("harshrawat: container exited: %s", container.ID())

			notification := &containerNotification{
				requestBase: requestBase{
					ContainerID: r.ContainerID,
					ActivityID:  r.ActivityID,
				},
				Operation:  "None",
				Result:     0,
				ResultInfo: anyInString{Value: ""},
			}
			_ = b.sendNotificationToShim(notification)
		}()

		// Send response back to shim
		return b.sendSuccessMessageToShim(req.activityID, rpcCreate, req.header.ID)
	}

	b.forwardRequestToGcs(req)
	return err
}

func (b *Bridge) startContainer(req *request) error {
	var r requestBase
	if err := json.Unmarshal(req.message, &r); err != nil {
		return fmt.Errorf("failed to unmarshal rpcStart: %v", req)
	}
	log.Printf("rpcStart: \n requestBase: %v", r)

	// Check if the container id is that of a job container. If so then no-op.
	if b.hostState.IsManagedContainer(r.ContainerID) {
		if err := b.hostState.StartContainer(context.Background(), r.ContainerID); err != nil {
			return fmt.Errorf("failed to start container: %w", err)
		}

		log.Printf("rawahars Started container: %v", r.ContainerID)

		// Send response back to shim
		return b.sendSuccessMessageToShim(req.activityID, rpcStart, req.header.ID)
	}

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) shutdownGraceful(req *request) error {
	var r requestBase
	if err := json.Unmarshal(req.message, &r); err != nil {
		return fmt.Errorf("failed to unmarshal rpcShutdownGraceful: %v", req)
	}
	log.Printf("rpcShutdownGraceful: \n requestBase: %v", r)

	// Since gcs-sidecar can be used for all types of windows
	// containers, it is important to check if we want to
	// enforce policy or not.
	if b.hostState.isSecurityPolicyEnforcerInitialized() {
		err := b.hostState.securityPolicyEnforcer.EnforceShutdownContainerPolicy(req.ctx, r.ContainerID)
		if err != nil {
			return fmt.Errorf("rpcShudownGraceful operation not allowed: %v", err)
		}
	}

	if b.hostState.IsManagedContainer(r.ContainerID) {
		if err := b.hostState.ShutdownContainer(context.Background(), r.ContainerID); err != nil {
			return fmt.Errorf("failed to shutdown container: %w", err)
		}

		// Send response back to shim
		return b.sendSuccessMessageToShim(req.activityID, rpcShutdownGraceful, req.header.ID)
	}

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) shutdownForced(req *request) error {
	var r requestBase
	if err := json.Unmarshal(req.message, &r); err != nil {
		return fmt.Errorf("failed to unmarshal rpcShutdownForced: %v", req)
	}
	log.Printf("rpcShutdownForced: \n requestBase: %v", r)

	if b.hostState.IsManagedContainer(r.ContainerID) {
		if err := b.hostState.TerminateContainer(context.Background(), r.ContainerID); err != nil {
			return fmt.Errorf("failed to terminate container: %w", err)
		}

		// Send response back to shim
		return b.sendSuccessMessageToShim(req.activityID, rpcShutdownForced, req.header.ID)
	}

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) executeProcess(req *request) error {
	var r containerExecuteProcess
	var processParamSettings json.RawMessage
	r.Settings.ProcessParameters.Value = &processParamSettings
	if err := json.Unmarshal(req.message, &r); err != nil {
		return fmt.Errorf("failed to unmarshal rpcExecuteProcess: %v", req)
	}
	containerID := r.requestBase.ContainerID
	stdioRelaySettings := r.Settings.StdioRelaySettings
	vsockStdioRelaySettings := r.Settings.VsockStdioRelaySettings

	var processParams hcsschema.ProcessParameters
	if err := json.Unmarshal(processParamSettings, &processParams); err != nil {
		log.Printf("rpcExecProcess: invalid params type for request %v", r.Settings)
		return fmt.Errorf("rpcExecProcess: invalid params type for request %v", r.Settings)
	}
	log.Printf("rpcExecProcess: \n containerID: %v, schema1.ProcessParameters{ params: %v, stdioRelaySettings: %v, vsockStdioRelaySettings: %v }", containerID, processParams, stdioRelaySettings, vsockStdioRelaySettings)

	if b.hostState.IsManagedContainer(r.ContainerID) {
		process, err := b.hostState.StartProcess(context.Background(), containerID, &processParams, stdioRelaySettings)
		if err != nil {
			return fmt.Errorf("rpcExecProcess: failed to start process: %w", err)
		}

		resp := &containerExecuteProcessResponse{
			responseBase: responseBase{
				Result:     0,
				ActivityID: r.ActivityID,
			},
			ProcessID: uint32(process.Pid()),
		}
		err = b.sendResponseToShim(rpcExecuteProcess, req.header.ID, resp)
		if err != nil {
			return fmt.Errorf("error sending reply to hcsshim: %w", err)
		}
		return nil
	}

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) waitForProcess(req *request) error {
	var r containerWaitForProcess
	if err := json.Unmarshal(req.message, &r); err != nil {
		return fmt.Errorf("failed to unmarshal waitForProcess: %v", req)
	}
	log.Printf("rpcWaitForProcess: \n containerWaitForProcess{ requestBase: %v, processID: %v, timeoutInMs: %v }", r.requestBase, r.ProcessID, r.TimeoutInMs)

	if b.hostState.IsManagedContainer(r.ContainerID) {
		exitCode, err := b.hostState.WaitOnProcess(r.ContainerID, r.ProcessID, r.TimeoutInMs)
		if err != nil {
			return err
		}

		resp := &containerWaitForProcessResponse{
			responseBase: responseBase{
				Result:     0,
				ActivityID: r.ActivityID,
			},
			ExitCode: exitCode,
		}
		err = b.sendResponseToShim(rpcWaitForProcess, req.header.ID, resp)
		if err != nil {
			return fmt.Errorf("error sending reply to hcsshim: %w", err)
		}
		return nil
	}

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) signalProcess(req *request) error {
	var r containerSignalProcess
	var rawOpts json.RawMessage
	r.Options = &rawOpts
	if err := json.Unmarshal(req.message, &r); err != nil {
		return fmt.Errorf("failed to unmarshal rpcSignalProcess: %v", req)
	}

	log.Printf("rpcSignalProcess: request %v", r)

	var wcowOptions guestresource.SignalProcessOptionsWCOW
	if rawOpts != nil {
		if err := json.Unmarshal(rawOpts, &wcowOptions); err != nil {
			log.Printf("rpcSignalProcess: invalid Options type for request %v", r)
			return fmt.Errorf("rpcSignalProcess: invalid Options type for request %v", r)
		}
	}
	log.Printf("rpcSignalProcess: \n containerSignalProcess{ requestBase: %v, processID: %v, Options: %v }", r.requestBase, r.ProcessID, wcowOptions)

	if b.hostState.IsManagedContainer(r.ContainerID) {
		err := b.hostState.SignalContainerProcess(context.Background(), r.ContainerID, r.ProcessID, wcowOptions)
		if err != nil {
			return fmt.Errorf("error signalling process: %w", err)
		}

		// Send response back to shim
		return b.sendSuccessMessageToShim(req.activityID, rpcSignalProcess, req.header.ID)
	}

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) resizeConsole(req *request) error {
	var r containerResizeConsole
	if err := json.Unmarshal(req.message, &r); err != nil {
		return fmt.Errorf("failed to unmarshal rpcSignalProcess: %v", req)
	}
	log.Printf("rpcResizeConsole: \n containerResizeConsole{ requestBase: %v, processID: %v, height: %v, width: %v }", r.requestBase, r.ProcessID, r.Height, r.Width)

	if b.hostState.IsManagedContainer(r.ContainerID) {
		err := b.hostState.ResizeConsole(context.Background(), r.ContainerID, r.ProcessID, r.Width, r.Height)
		if err != nil {
			return fmt.Errorf("error resizing console: %w", err)
		}

		// Send response back to shim
		return b.sendSuccessMessageToShim(req.activityID, rpcResizeConsole, req.header.ID)
	}

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) getProperties(req *request) error {
	// TODO: This has containerGetProperties and containerGetPropertiesV2. Need to find a way to differentiate!
	/*
		var r containerGetProperties
		if err := json.Unmarshal(req.message, &r); err != nil {
			return fmt.Errorf("failed to unmarshal rpcSignalProcess: %v", req)
		}
	*/
	// TODO: Error out if v1 schema is being used as we will not support bringing up sidecar-gcs there
	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) negotiateProtocol(req *request) error {
	var r negotiateProtocolRequest
	if err := json.Unmarshal(req.message, &r); err != nil {
		return fmt.Errorf("failed to unmarshal rpcNegotiateProtocol: %v", req)
	}
	log.Printf("rpcNegotiateProtocol: negotiateProtocolRequest{ requestBase %v, MinVersion: %v, MaxVersion: %v }", r.requestBase, r.MinimumVersion, r.MaximumVersion)

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) dumpStacks(req *request) error {
	var r dumpStacksRequest
	if err := json.Unmarshal(req.message, &r); err != nil {
		return fmt.Errorf("failed to unmarshal rpcStart: %v", req)
	}

	if b.hostState.isSecurityPolicyEnforcerInitialized() {
		err := b.hostState.securityPolicyEnforcer.EnforceDumpStacksPolicy(req.ctx)
		if err != nil {
			return errors.Wrapf(err, "dump stacks denied due to policy")
		}
	}

	log.Printf("rpcDumpStacks: \n requestBase: %v", r.requestBase)

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) deleteContainerState(req *request) error {
	var r deleteContainerStateRequest
	if err := json.Unmarshal(req.message, &r); err != nil {
		return fmt.Errorf("failed to unmarshal rpcStart: %v", req)
	}
	log.Printf("rpcDeleteContainerRequest: \n requestBase: %v", r.requestBase)

	if b.hostState.IsManagedContainer(r.ContainerID) {
		err := b.hostState.RemoveContainerState(r.ContainerID)
		if err != nil {
			return fmt.Errorf("error removing container state: %w", err)
		}

		// Send response back to shim
		return b.sendSuccessMessageToShim(req.activityID, rpcDeleteContainerState, req.header.ID)
	}

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) updateContainer(req *request) error {
	// No callers in the code for rpcUpdateContainer
	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) lifecycleNotification(req *request) error {
	// No callers in the code for rpcLifecycleNotification
	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) modifySettings(req *request) error {
	log.Printf("\n, modifySettings:Header {Type: %v Size: %v ID: %v }\n msg: %v \n", req.header.Type, req.header.Size, req.header.ID, string(req.message))
	modifyRequest, err := unmarshalContainerModifySettings(req)
	if err != nil {
		return err
	}
	modifyGuestSettingsRequest := modifyRequest.Request.(*guestrequest.ModificationRequest)
	guestResourceType := modifyGuestSettingsRequest.ResourceType
	guestRequestType := modifyGuestSettingsRequest.RequestType // add, remove, preadd, update
	log.Printf("rpcModifySettings: guestRequest.ModificationRequest { resourceType: %v \n, requestType: %v", guestResourceType, guestRequestType)

	containerID := modifyRequest.ContainerID
	if containerID != nullContainerID && b.hostState.IsManagedContainer(containerID) {
		if err = b.hostState.ModifyContainer(context.Background(), containerID, modifyGuestSettingsRequest); err != nil {
			return fmt.Errorf("failed to modify container: %w", err)
		}

		// Send response back to shim
		return b.sendSuccessMessageToShim(req.activityID, rpcModifySettings, req.header.ID)
	}

	// TODO: Do we need to validate request types?
	switch guestRequestType {
	case guestrequest.RequestTypeAdd:
	case guestrequest.RequestTypeRemove:
	case guestrequest.RequestTypePreAdd:
	case guestrequest.RequestTypeUpdate:
	default:
		log.Printf("\n Invald guestRequestType: %v", guestRequestType)
		return fmt.Errorf("invald guestRequestType %v", guestRequestType)
	}

	if guestResourceType != "" {
		switch guestResourceType {
		case guestresource.ResourceTypeCombinedLayers:
			settings := modifyGuestSettingsRequest.Settings.(*guestresource.WCOWCombinedLayers)
			log.Printf(", WCOWCombinedLayers {ContainerRootPath: %v, Layers: %v, ScratchPath: %v} \n", settings.ContainerRootPath, settings.Layers, settings.ScratchPath)

		case guestresource.ResourceTypeNetworkNamespace:
			settings := modifyGuestSettingsRequest.Settings.(*hcn.HostComputeNamespace)
			log.Printf(", HostComputeNamespaces { %v} \n", settings)

		case guestresource.ResourceTypeNetwork:
			settings := modifyGuestSettingsRequest.Settings.(*guestrequest.NetworkModifyRequest)
			log.Printf(", NetworkModifyRequest { %v} \n", settings)

		case guestresource.ResourceTypeMappedVirtualDisk:
			wcowMappedVirtualDisk := modifyGuestSettingsRequest.Settings.(*guestresource.WCOWMappedVirtualDisk)
			// TODO: For verified cims (Cimfs API not ready yet)
			log.Printf(", wcowMappedVirtualDisk { %v} \n", wcowMappedVirtualDisk)

		case guestresource.ResourceTypeHvSocket:
			log.Printf("guestresource.ResourceTypeHvSocket \n")
			hvSocketAddress := modifyGuestSettingsRequest.Settings.(*hcsschema.HvSocketAddress)
			log.Printf(", hvSocketAddress { %v} \n", hvSocketAddress)

		case guestresource.ResourceTypeMappedDirectory:
			log.Printf("guestresource.ResourceTypeMappedDirectory \n")
			settings := modifyGuestSettingsRequest.Settings.(*hcsschema.MappedDirectory)
			log.Printf(", hcsschema.MappedDirectory { %v } \n", settings)

		case guestresource.ResourceTypeSecurityPolicy:
			securityPolicyRequest := modifyGuestSettingsRequest.Settings.(*guestresource.WCOWConfidentialOptions)
			log.Printf(", WCOWConfidentialOptions: { %v} \n", securityPolicyRequest)
			_ = b.hostState.SetWCOWConfidentialUVMOptions( /*ctx, */ securityPolicyRequest)

			// Send response back to shim
			resp := &responseBase{
				Result:     0, // 0 means success
				ActivityID: req.activityID,
			}
			err := b.sendResponseToShim(rpcModifySettings, req.header.ID, resp)
			if err != nil {
				log.Printf("error sending response to hcsshim: %v", err)
				return fmt.Errorf("error sending early reply back to hcsshim")
			}
			return nil

		case guestresource.ResourceTypeWCOWBlockCims:
			// This is request to mount the merged cim at given volumeGUID
			wcowBlockCimMounts := modifyGuestSettingsRequest.Settings.(*guestresource.WCOWBlockCIMMounts)
			log.Printf(", WCOWBlockCIMMounts { %v} \n", wcowBlockCimMounts)

			var mergedCim cimfs.BlockCIM
			var sourceCims []*cimfs.BlockCIM
			ctx := context.Background()
			for i, blockCimDevice := range wcowBlockCimMounts.BlockCIMs {
				// Get the scsi device path for the blockCim lun
				scsiDevPath, _, err := windevice.GetScsiDevicePathAndDiskNumberFromControllerLUN(
					ctx,
					0, /* controller is always 0 for wcow */
					uint8(blockCimDevice.Lun))
				if err != nil {
					log.Printf("err getting scsiDevPath: %v", err)
					return err
				}
				if i == 0 {
					// BlockCIMs should be ordered from merged CIM followed by Layer n .. layer 1
					mergedCim = cimfs.BlockCIM{
						Type:      cimfs.BlockCIMTypeDevice,
						BlockPath: scsiDevPath,
						CimName:   blockCimDevice.CimName,
					}
				} else {
					layerCim := cimfs.BlockCIM{
						Type:      cimfs.BlockCIMTypeDevice,
						BlockPath: scsiDevPath,
						CimName:   blockCimDevice.CimName,
					}
					sourceCims = append(sourceCims, &layerCim)
				}
			}

			// Get the topmost merge CIM and invoke the MountMergedBlockCIMs
			_, err := cimfs.MountMergedBlockCIMs(&mergedCim, sourceCims, wcowBlockCimMounts.MountFlags, wcowBlockCimMounts.VolumeGuid)
			if err != nil {
				return fmt.Errorf("error mounting merged block cims: %v", err)
			}
			// Send response back to shim
			resp := &responseBase{
				Result:     0, // 0 means success
				ActivityID: req.activityID,
			}
			err = b.sendResponseToShim(rpcModifySettings, req.header.ID, resp)
			if err != nil {
				log.Printf("error sending response to hcsshim: %v", err)
				return fmt.Errorf("error sending early reply back to hcsshim")
			}
			return nil

		case guestresource.ResourceTypeCWCOWCombinedLayers:
			settings := modifyGuestSettingsRequest.Settings.(*guestresource.CWCOWCombinedLayers)
			containerID := settings.ContainerID
			log.Printf(", CWCOWCombinedLayers {ContainerID: %v {ContainerRootPath: %v, Layers: %v, ScratchPath: %v}} \n",
				containerID, settings.CombinedLayers.ContainerRootPath, settings.CombinedLayers.Layers, settings.CombinedLayers.ScratchPath)

			// TODO: Update modifyCombinedLayers with verified CimFS API
			if b.hostState.isSecurityPolicyEnforcerInitialized() {
				policy_err := modifyCombinedLayers(req.ctx, containerID, guestRequestType, settings.CombinedLayers, b.hostState.securityPolicyEnforcer)
				if policy_err != nil {
					return fmt.Errorf("CimFS layer mount is denied by policy: %v", modifyRequest)
				}
			}

			// Reconstruct WCOWCombinedLayers{} and req before forwarding to GCS
			// as GCS does not understand containerID in CombinedLayers request
			modifyGuestSettingsRequest.ResourceType = guestresource.ResourceTypeCombinedLayers
			modifyGuestSettingsRequest.Settings = settings.CombinedLayers
			modifyRequest.Request = modifyGuestSettingsRequest
			buf, err := json.Marshal(modifyRequest)
			if err != nil {
				return fmt.Errorf("failed to marshal rpcModifySettings: %v", req)
			}

			// The following two folders are expected to be present in thr scratch.
			// But since we have just formatted the scratch we would need to
			// create them manually.
			sandboxStateDirectory := filepath.Join(settings.CombinedLayers.ContainerRootPath, sandboxStateDirName)
			err = os.Mkdir(sandboxStateDirectory, 0777)
			if err != nil {
				log.Printf("unexpected error creating sandboxStateDirectory: %v", err)
				return fmt.Errorf("unexpected error sandboxStateDirectory: %v", err)
			}

			hivesDirectory := filepath.Join(settings.CombinedLayers.ContainerRootPath, hivesDirName)
			err = os.Mkdir(hivesDirectory, 0777)
			if err != nil {
				log.Printf("unexpected error creating hivesDirectory: %v", err)
				return fmt.Errorf("unexpected error hivesDirectory: %v", err)
			}

			var newRequest request
			newRequest.header = req.header
			newRequest.header.Size = uint32(len(buf)) + hdrSize
			newRequest.message = buf
			req = &newRequest

		case guestresource.ResourceTypeMappedVirtualDiskForContainerScratch:
			wcowMappedVirtualDisk := modifyGuestSettingsRequest.Settings.(*guestresource.WCOWMappedVirtualDisk)
			log.Printf(", wcowMappedVirtualDisk { %v} \n", wcowMappedVirtualDisk)

			// 1.TODO: Need to enforce policy before calling into fsFormatter
			// 2. Then call fsFormatter to format the scratch disk.
			// This will return the volume path of the mounted scratch.
			// Scratch disk should be >= 30 GB for refs formatter to work.

			// fsFormatter understands only virtualDevObjectPathFormat. Therefore fetch the
			// disk number for the corresponding lun
			var diskNumber uint64
			// It could take a few seconds for the attached scsi disk
			// to show up inside the UVM. Therefore adding retry logic
			// with delay here.
			for i := 0; i < 5; i++ {
				time.Sleep(5 * time.Second)
				_, diskNumber, err := windevice.GetScsiDevicePathAndDiskNumberFromControllerLUN(req.ctx,
					0, /* Only one controller allowed in wcow hyperv */
					uint8(wcowMappedVirtualDisk.Lun))
				if err != nil {
					if i == 4 {
						// bail out
						log.Printf("error getting diskNumber for LUN %d, err : %v", wcowMappedVirtualDisk.Lun, err)
						return fmt.Errorf("error getting diskNumber for LUN %d", wcowMappedVirtualDisk.Lun)
					}
					continue
				} else {
					log.Printf("DiskNumber of lun %d is:  %d", wcowMappedVirtualDisk.Lun, diskNumber)
				}
			}
			diskPath := fmt.Sprintf(fsformatter.VirtualDevObjectPathFormat, diskNumber)
			log.Printf("\n diskPath: %v, diskNumber: %v ", diskPath, diskNumber)
			mountedVolumePath, err := windevice.InvokeFsFormatter(req.ctx, diskPath)
			if err != nil {
				log.Printf("\n InvokeFsFormatter returned err: %v", err)
				return err
			}
			log.Printf("\n mountedVolumePath returned from InvokeFsFormatter: %v", mountedVolumePath)

			// Just forward the req as is to inbox gcs and let it retreive the volume.
			// While forwarding request to inbox gcs, make sure to replace
			// the resourceType to ResourceTypeMappedVirtualDisk that it
			// understands.
			modifyGuestSettingsRequest.ResourceType = guestresource.ResourceTypeMappedVirtualDisk
			modifyRequest.Request = modifyGuestSettingsRequest
			buf, err := json.Marshal(modifyRequest)
			if err != nil {
				return fmt.Errorf("failed to marshal rpcModifySettings: %v", req)
			}

			var newRequest request
			newRequest.header = req.header
			newRequest.header.Size = uint32(len(buf))
			newRequest.message = buf
			req = &newRequest

		default:
			// Invalid request
			log.Printf("\n Invald modifySettingsRequest: %v", guestResourceType)
			return fmt.Errorf("invald modifySettingsRequest: %v", guestResourceType)
		}
	}

	b.forwardRequestToGcs(req)
	return nil
}
