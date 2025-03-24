//go:build windows

package windevice

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf16"
	"unsafe"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Microsoft/hcsshim/internal/fsformatter"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/winapi"
	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

const (
	_CM_GETIDLIST_FILTER_BUSRELATIONS uint32 = 0x00000020

	_CM_LOCATE_DEVNODE_NORMAL uint32 = 0x00000000

	_DEVPROP_TYPE_STRING      uint32 = 0x00000012
	_DEVPROP_TYPEMOD_LIST     uint32 = 0x00002000
	_DEVPROP_TYPE_STRING_LIST uint32 = (_DEVPROP_TYPE_STRING | _DEVPROP_TYPEMOD_LIST)

	_DEVPKEY_LOCATIONPATHS_GUID = "a45c254e-df1c-4efd-8020-67d146a850e0"

	_IOCTL_SCSI_GET_ADDRESS = 0x41018

	_IOCTL_STORAGE_GET_DEVICE_NUMBER = 0x2d1080

	_IOCTL_KERNEL_FORMAT_VOLUME_FORMAT = 0x40001000
)

var (
	// class GUID for devices with interface type Disk
	// 53f56307-b6bf-11d0-94f2-00a0c91efb8b
	devClassDiskGUID = guid.GUID{
		Data1: 0x53f56307,
		Data2: 0xb6bf,
		Data3: 0x11d0,
		Data4: [8]byte{0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b},
	}
)

// https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-storage_device_number
type STORAGE_DEVICE_NUMBER struct {
	DeviceType      uint32
	DeviceNumber    uint32
	PartitionNumber uint32
}

// SCSI_ADDRESS structure used with IOCTL_SCSI_GET_ADDRESS.
// defined here: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddscsi/ns-ntddscsi-_scsi_address
type SCSIAddress struct {
	Length     uint32
	PortNumber uint8
	PathId     uint8
	TargetId   uint8
	Lun        uint8
}

// getScsiAddress retrieves the SCSI address from a given disk handle
func getScsiAddress(handle windows.Handle) (*SCSIAddress, error) {
	// Create a SCSI_ADDRESS structure to receive the address information
	address := &SCSIAddress{}
	address.Length = uint32(unsafe.Sizeof(SCSIAddress{}))

	// Buffer for the returned data
	var bytesReturned uint32

	// Call DeviceIoControl with IOCTL_SCSI_GET_ADDRESS
	err := windows.DeviceIoControl(
		handle,
		_IOCTL_SCSI_GET_ADDRESS,
		nil, 0, // no input buffer
		(*byte)(unsafe.Pointer(address)),
		address.Length, &bytesReturned, nil)
	if err != nil {
		return nil, fmt.Errorf("DeviceIoControl failed with error: %w", err)
	}
	if bytesReturned <= 0 {
		return nil, fmt.Errorf("DeviceIoControl returned %d bytes", bytesReturned)
	}
	return address, nil
}

// getDevPKeyDeviceLocationPaths creates a DEVPROPKEY struct for the
// DEVPKEY_Device_LocationPaths property as defined in devpkey.h
func getDevPKeyDeviceLocationPaths() (*winapi.DevPropKey, error) {
	guid, err := guid.FromString(_DEVPKEY_LOCATIONPATHS_GUID)
	if err != nil {
		return nil, err
	}
	return &winapi.DevPropKey{
		Fmtid: guid,
		// pid value is defined in devpkey.h
		Pid: 37,
	}, nil
}

func GetDeviceLocationPathsFromIDs(ids []string) ([]string, error) {
	result := []string{}
	devPKeyDeviceLocationPaths, err := getDevPKeyDeviceLocationPaths()
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		var devNodeInst uint32
		err = winapi.CMLocateDevNode(&devNodeInst, id, _CM_LOCATE_DEVNODE_NORMAL)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to locate device node for %s", id)
		}
		propertyType := uint32(0)
		propertyBufferSize := uint32(0)

		// get the size of the property buffer by querying with a nil buffer and zeroed propertyBufferSize
		err = winapi.CMGetDevNodeProperty(devNodeInst, devPKeyDeviceLocationPaths, &propertyType, nil, &propertyBufferSize, 0)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get property buffer size of devnode query for %s with", id)
		}

		// get the property with the resulting propertyBufferSize
		propertyBuffer := make([]uint16, propertyBufferSize/2)
		err = winapi.CMGetDevNodeProperty(devNodeInst, devPKeyDeviceLocationPaths, &propertyType, &propertyBuffer[0], &propertyBufferSize, 0)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get location path property from device node for %s with", id)
		}
		if propertyType != _DEVPROP_TYPE_STRING_LIST {
			return nil, fmt.Errorf("expected to return property type DEVPROP_TYPE_STRING_LIST %d, instead got %d", _DEVPROP_TYPE_STRING_LIST, propertyType)
		}
		if int(propertyBufferSize/2) > len(propertyBuffer) {
			return nil, fmt.Errorf("location path is too large for the buffer, size in bytes %d", propertyBufferSize)
		}

		formattedResult, err := convertFirstNullTerminatedValueToString(propertyBuffer[:propertyBufferSize/2])
		if err != nil {
			return nil, err
		}
		result = append(result, formattedResult)
	}

	return result, nil
}

// helper function that finds the first \u0000 rune and returns the wide string as a regular go string
func convertFirstNullTerminatedValueToString(buf []uint16) (string, error) {
	r := utf16.Decode(buf)
	converted := string(r)
	zerosIndex := strings.IndexRune(converted, '\u0000')
	if zerosIndex == -1 {
		return "", errors.New("cannot convert value to string, malformed data passed")
	}
	return converted[:zerosIndex], nil
}

func convertNullSeparatedUint16BufToStringSlice(buf []uint16) []string {
	result := []string{}
	r := utf16.Decode(buf)
	converted := string(r)
	for {
		i := strings.IndexRune(converted, '\u0000')
		if i <= 0 {
			break
		}
		result = append(result, string(converted[:i]))
		converted = converted[i+1:]
	}
	return result
}

func GetChildrenFromInstanceIDs(parentIDs []string) ([]string, error) {
	var result []string
	for _, id := range parentIDs {
		pszFilterParentID := []byte(id)
		children, err := getDeviceIDList(&pszFilterParentID[0], _CM_GETIDLIST_FILTER_BUSRELATIONS)
		if err != nil {
			return nil, err
		}
		result = append(result, children...)
	}
	return result, nil
}

func getDeviceIDList(pszFilter *byte, ulFlags uint32) ([]string, error) {
	listLength := uint32(0)
	if err := winapi.CMGetDeviceIDListSize(&listLength, pszFilter, ulFlags); err != nil {
		return nil, err
	}
	if listLength == 0 {
		return []string{}, nil
	}
	buf := make([]byte, listLength)
	if err := winapi.CMGetDeviceIDList(pszFilter, &buf[0], uint32(listLength), ulFlags); err != nil {
		return nil, err
	}

	return winapi.ConvertStringSetToSlice(buf)
}

func getDeviceHandleFromPath(devPath string) (windows.Handle, error) {
	utf16Path, err := windows.UTF16PtrFromString(devPath)
	if err != nil {
		return windows.Handle(unsafe.Pointer(nil)), fmt.Errorf("failed to convert interface path [%s] to utf16: %w", devPath, err)
	}

	handle, err := windows.CreateFile(utf16Path, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return windows.Handle(unsafe.Pointer(nil)), fmt.Errorf("failed to get handle to interface path [%s]: %w", devPath, err)
	}
	return handle, nil
}

func getDeviceInterfaceList(ctx context.Context, controller, lun uint8) ([]string, error) {
	// get a list of all disk device interfaces
	interfaceListSize := uint32(0)
	if err := winapi.CMGetDeviceInterfaceListSize(&interfaceListSize, &devClassDiskGUID, nil, 0); err != nil {
		return nil, fmt.Errorf("failed to get size of disk device interface list: %w", err)
	}

	buf := make([]uint16, interfaceListSize)
	if err := winapi.CMGetDeviceInterfaceList(&devClassDiskGUID, nil, &buf[0], interfaceListSize, 0); err != nil {
		return nil, fmt.Errorf("failed to get disk device interface list: %w", err)
	}

	interfacePaths := convertNullSeparatedUint16BufToStringSlice(buf)
	log.G(ctx).Debugf("disk device interface list size: %d", len(interfacePaths))
	log.G(ctx).WithField("list", interfacePaths).Trace("disk device interfaces")

	return interfacePaths, nil
}

// GetScsiDevicePathAndDiskNumberFromControllerLUN finds a storage device that has the matching
// `controller` and `LUN` and returns its scsi device path and corresponding disk number.
func GetScsiDevicePathAndDiskNumberFromControllerLUN(ctx context.Context, controller, LUN uint8) (string, uint64, error) {
	interfacePaths, err := getDeviceInterfaceList(ctx, controller, LUN)
	if err != nil {
		return "", 0, err
	}
	// go over each disk device interface and find out its LUN
	for _, iPath := range interfacePaths {
		handle, err := getDeviceHandleFromPath(iPath)
		if err != nil {
			return "", 0, err
		}
		defer windows.Close(handle)

		scsiAddr, err := getScsiAddress(handle)
		if err != nil {
			return "", 0, fmt.Errorf("failed to get SCSI address for interface path [%s]: %w", iPath, err)
		}

		// TODO(ambarve): is comparing controller with port number the correct way?
		if scsiAddr.Lun == LUN && scsiAddr.PortNumber == controller {
			// get the disk number
			var bytesReturned uint32
			var deviceNumber STORAGE_DEVICE_NUMBER
			if err := windows.DeviceIoControl(
				handle,
				_IOCTL_STORAGE_GET_DEVICE_NUMBER,
				nil, 0, // No input buffer
				(*byte)(unsafe.Pointer(&deviceNumber)),
				uint32(unsafe.Sizeof(deviceNumber)),
				&bytesReturned,
				nil,
			); err != nil {
				return "", 0, err
			}
			return iPath, uint64(deviceNumber.DeviceNumber), nil
		}
	}
	return "", 0, fmt.Errorf("no device found with controller: %d & LUN:%d", controller, LUN)
}

// InvokeFsFormatter makes an ioctl call to the fsFormatter driver and returns
// a path to the mountedVolume
func InvokeFsFormatter(ctx context.Context, diskPath string) (string, error) {
	// Prepare input and output buffers as expected by fsFormatter
	inputBuffer := fsformatter.KmFmtCreateFormatInputBuffer(diskPath)
	outputBuffer := fsformatter.KmFmtCreateFormatOutputBuffer()

	utf16DriverPath, _ := windows.UTF16PtrFromString(fsformatter.KERNEL_FORMAT_VOLUME_WIN32_DRIVER_PATH)
	deviceHandle, err := windows.CreateFile(utf16DriverPath,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		0,
		nil,
		windows.OPEN_EXISTING,
		0,
		0)
	if err != nil {
		return "", fmt.Errorf("error getting handle to fsFormatter driver: %v", err)
	}
	defer windows.Close(deviceHandle)

	// Ioctl to fsFormatter driver
	var bytesReturned uint32
	if err := windows.DeviceIoControl(
		deviceHandle,
		_IOCTL_KERNEL_FORMAT_VOLUME_FORMAT,
		(*byte)(unsafe.Pointer(inputBuffer)),
		uint32(inputBuffer.Size),
		(*byte)(unsafe.Pointer(outputBuffer)),
		outputBuffer.Size,
		&bytesReturned,
		nil,
	); err != nil {
		return "", err
	}

	// Read the returned volume path from the corresponding offset in outputBuffer
	ptr := unsafe.Pointer(uintptr(unsafe.Pointer(outputBuffer)) + uintptr(fsformatter.GetVolumePathBufferOffset()))
	var result []byte
	for i := 0; i < int(outputBuffer.VolumePathLength); i++ {
		// Read each byte (this is unsafe, but for illustrative purposes)
		byteVal := *((*byte)(unsafe.Pointer(uintptr(ptr) + uintptr(i))))
		result = append(result, byteVal)
	}

	mountedVolumePath := string(result)
	log.G(ctx).Debugf("MountedVolumePath returned: %v", mountedVolumePath)

	return mountedVolumePath, err
}
