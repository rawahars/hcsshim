package fsformatter

import (
	"encoding/binary"
	"log"
	"unicode/utf16"
	"unsafe"
)

const (
	// This is used to construct the disk path that fsFormatter
	// understands. `harddisk%d` here refers to the disk number
	// associated with the corresponding lun of the attached
	// scsi device.
	VirtualDevObjectPathFormat                              = "\\device\\harddisk%d\\partition0"
	CHECKSUM_TYPE_SHA256                                    = uint16(4)
	REFS_CHECKSUM_TYPE                                      = CHECKSUM_TYPE_SHA256
	MAX_SIZE_OF_KERNEL_FORMAT_VOLUME_FORMAT_REFS_PARAMETERS = 16 * 8 // 128 bytes
	SIZE_OF_WCHAR                                           = int(unsafe.Sizeof(uint16(0)))
	KERNEL_FORMAT_VOLUME_MAX_VOLUME_LABEL_LENGTH            = uint32(33 * SIZE_OF_WCHAR)
	KERNEL_FORMAT_VOLUME_WIN32_DRIVER_PATH                  = "\\\\?\\KernelFSFormatter"
	// Allocate large enough buffer for output from fsFormatter
	MAX_SIZE_OF_OUTPUT_BUFFER = uint32(512)
)

type KERNEL_FORMAT_VOLUME_FILESYSTEM_TYPES uint32

const (
	KERNEL_FORMAT_VOLUME_FILESYSTEM_TYPE_INVALID = KERNEL_FORMAT_VOLUME_FILESYSTEM_TYPES(iota)
	KERNEL_FORMAT_VOLUME_FILESYSTEM_TYPE_REFS    = KERNEL_FORMAT_VOLUME_FILESYSTEM_TYPES(1)
	KERNEL_FORMAT_VOLUME_FILESYSTEM_TYPE_MAX     = KERNEL_FORMAT_VOLUME_FILESYSTEM_TYPES(2)
)

// We only want to allow refs formatting
func (filesystemType KERNEL_FORMAT_VOLUME_FILESYSTEM_TYPES) String() string {
	switch filesystemType {
	case KERNEL_FORMAT_VOLUME_FILESYSTEM_TYPE_REFS:
		return "KERNEL_FORMAT_VOLUME_FILESYSTEM_TYPE_REFS"
	default:
		return "Unknown"
	}
}

type KERNEL_FORMAT_VOLUME_FORMAT_INPUT_BUFFER_FLAGS uint32

const KERNEL_FORMAT_VOLUME_FORMAT_INPUT_BUFFER_FLAG_NONE = KERNEL_FORMAT_VOLUME_FORMAT_INPUT_BUFFER_FLAGS(0x00000000)

func (flag KERNEL_FORMAT_VOLUME_FORMAT_INPUT_BUFFER_FLAGS) String() string {
	switch flag {
	case KERNEL_FORMAT_VOLUME_FORMAT_INPUT_BUFFER_FLAG_NONE:
		return "KERNEL_FORMAT_VOLUME_FORMAT_INPUT_BUFFER_FLAG_NONE"
	default:
		return "Unknown"
	}
}

type KernelFormatVolumeFormatRefsParameters struct {
	ClusterSize          uint32
	MetadataChecksumType uint16
	UseDataIntegrity     bool
	MajorVersion         uint16
	MinorVersion         uint16
}

type KernelFormatVolumeFormatFsParameters struct {
	FileSystemType KERNEL_FORMAT_VOLUME_FILESYSTEM_TYPES
	// Represents a WCHAR character array
	VolumeLabel [KERNEL_FORMAT_VOLUME_MAX_VOLUME_LABEL_LENGTH / uint32(SIZE_OF_WCHAR)]uint16
	// Length of volume label in bytes
	VolumeLabelLength uint16
	// RefsFormatterParams represents the following union
	/*
	   union {

	       KERNEL_FORMAT_VOLUME_FORMAT_REFS_PARAMETERS RefsParameters;

	       //
	       //  This structure can't grow in size nor change in alignment. 16 ULONGLONGs
	       //  should be more than enough for supporting other filesystems down the
	       //  line. This also serves to enforce 8 byte alignment.
	       //
	       Reserved [16]uint64
	   };
	*/
	RefsFormatterParams [128]byte
}

type KernelFormatVolumeFormatInputBuffer struct {
	Size         uint64
	FsParameters KernelFormatVolumeFormatFsParameters
	Flags        KERNEL_FORMAT_VOLUME_FORMAT_INPUT_BUFFER_FLAGS
	Reserved     [4]uint32
	// Size of DiskPathBuffer in bytes
	DiskPathLength uint16
	// DiskPathBuffer holds the disk path. It represents a
	// variable size WCHAR character array
	DiskPathBuffer []uint16
}

type KERNEL_FORMAT_VOLUME_FORMAT_OUTPUT_BUFFER_FLAGS uint32

const KERNEL_FORMAT_VOLUME_FORMAT_OUTPUT_BUFFER_FLAG_NONE = KERNEL_FORMAT_VOLUME_FORMAT_OUTPUT_BUFFER_FLAGS(0x00000000)

func (flag KERNEL_FORMAT_VOLUME_FORMAT_OUTPUT_BUFFER_FLAGS) String() string {
	switch flag {
	case KERNEL_FORMAT_VOLUME_FORMAT_OUTPUT_BUFFER_FLAG_NONE:
		return "KERNEL_FORMAT_VOLUME_FORMAT_OUTPUT_BUFFER_FLAG_NONE"
	default:
		return "Unknown"
	}
}

type KernelFormarVolumeFormatOutputBuffer struct {
	Size     uint32
	Flags    KERNEL_FORMAT_VOLUME_FORMAT_OUTPUT_BUFFER_FLAGS
	Reserved [4]uint32
	// VolumePathLength holds size of VolumePathBuffer
	// in bytes
	VolumePathLength uint16
	// VolumePathBuffer holds the mounted volume path
	// as returned from fsFormatter. It represents
	// a variable size WCHAR character array
	VolumePathBuffer []uint16
}

// GetVolumePathBufferOffset gets offset to KernelFormarVolumeFormatOutputBuffer{}.VolumePathBuffer
func GetVolumePathBufferOffset() uint32 {
	volPathBufferOffset := uint32(unsafe.Sizeof(KernelFormarVolumeFormatOutputBuffer{}.Size) +
		unsafe.Sizeof(KernelFormarVolumeFormatOutputBuffer{}.Flags) +
		unsafe.Sizeof(KernelFormarVolumeFormatOutputBuffer{}.Reserved) +
		unsafe.Sizeof(KernelFormarVolumeFormatOutputBuffer{}.VolumePathLength))

	return volPathBufferOffset
}

// getInputBufferSize gets the total size needed for input buffer
func getInputBufferSize(wcharDiskPathLength uint16) uint32 {
	bufferSize := uint32(unsafe.Sizeof(KernelFormatVolumeFormatInputBuffer{}.Size)+
		unsafe.Offsetof(KernelFormatVolumeFormatFsParameters{}.RefsFormatterParams)+
		/* this is specifically for the union inKernelFormatVolumeFormatFsParameters */
		MAX_SIZE_OF_KERNEL_FORMAT_VOLUME_FORMAT_REFS_PARAMETERS+
		unsafe.Sizeof(KernelFormatVolumeFormatInputBuffer{}.Flags)+
		unsafe.Sizeof(KernelFormatVolumeFormatInputBuffer{}.Reserved)+
		unsafe.Sizeof(KernelFormatVolumeFormatInputBuffer{}.DiskPathLength)) +
		uint32(wcharDiskPathLength)

	return bufferSize
}

// getInputBufferDiskPathBufferOffset gets offset to KernelFormatVolumeFormatInputBuffer{}.DiskPathBuffer
func getInputBufferDiskPathBufferOffset() uint32 {
	diskPathBufferOffset := uint32(unsafe.Sizeof(KernelFormatVolumeFormatInputBuffer{}.Size) +
		unsafe.Offsetof(KernelFormatVolumeFormatFsParameters{}.RefsFormatterParams) +
		MAX_SIZE_OF_KERNEL_FORMAT_VOLUME_FORMAT_REFS_PARAMETERS +
		unsafe.Sizeof(KernelFormatVolumeFormatInputBuffer{}.Flags) +
		unsafe.Sizeof(KernelFormatVolumeFormatInputBuffer{}.Reserved) +
		unsafe.Sizeof(KernelFormatVolumeFormatInputBuffer{}.DiskPathLength))

	return diskPathBufferOffset
}

// KmFmtCreateFormatOutputBuffer formats an output buffer as expected
// by the fsFormatter driver
func KmFmtCreateFormatOutputBuffer() *KernelFormarVolumeFormatOutputBuffer {
	buf := make([]uint16, MAX_SIZE_OF_OUTPUT_BUFFER)
	outputBuffer := (*KernelFormarVolumeFormatOutputBuffer)(unsafe.Pointer(&buf[0]))
	outputBuffer.Size = uint32(MAX_SIZE_OF_OUTPUT_BUFFER)

	return outputBuffer
}

// KmFmtCreateFormatInputBuffer formats an input buffer as expected
// by the fsFormatter driver.
// diskPath represents disk path in VirtualDevObjectPathFormat.
func KmFmtCreateFormatInputBuffer(diskPath string) *KernelFormatVolumeFormatInputBuffer {
	refsParametersBuf := make([]byte, unsafe.Sizeof(KernelFormatVolumeFormatRefsParameters{}))
	refsParameters := (*KernelFormatVolumeFormatRefsParameters)(unsafe.Pointer(&refsParametersBuf[0]))

	utf16DiskPath := utf16.Encode([]rune(diskPath))
	wcharDiskPathLength := uint16(len(utf16DiskPath) * SIZE_OF_WCHAR)

	refsParameters.ClusterSize = 0x1000
	refsParameters.MetadataChecksumType = REFS_CHECKSUM_TYPE
	refsParameters.UseDataIntegrity = true
	refsParameters.MajorVersion = uint16(3)
	refsParameters.MinorVersion = uint16(14)

	bufferSize := getInputBufferSize(wcharDiskPathLength)
	log.Printf("\n Input buffer size: %v bytes", bufferSize)
	buf := make([]byte, bufferSize) // bufferSize)
	inputBuffer := (*KernelFormatVolumeFormatInputBuffer)(unsafe.Pointer(&buf[0]))

	inputBuffer.Size = uint64(bufferSize)
	inputBuffer.Flags = KERNEL_FORMAT_VOLUME_FORMAT_INPUT_BUFFER_FLAG_NONE

	inputBuffer.FsParameters.FileSystemType = KERNEL_FORMAT_VOLUME_FILESYSTEM_TYPE_REFS
	// Not setting inputBuffer.FsParameters.VolumeLabel to leave it empty
	inputBuffer.FsParameters.VolumeLabelLength = 0 // Scratch disk need not be partitioned. Therefore pass wchar empty string.
	inputBuffer.FsParameters.VolumeLabel = [33]uint16{}

	// Write KERNEL_FORMAT_VOLUME_FORMAT_REFS_PARAMETERS
	// Write the ClusterSize (8 bytes)
	binary.LittleEndian.PutUint32(inputBuffer.FsParameters.RefsFormatterParams[0:], refsParameters.ClusterSize)
	// Write the MetadataChecksumType (2 bytes)
	binary.LittleEndian.PutUint16(inputBuffer.FsParameters.RefsFormatterParams[4:], refsParameters.MetadataChecksumType)
	// Write the UseDataIntegrity (1 byte)
	if refsParameters.UseDataIntegrity {
		inputBuffer.FsParameters.RefsFormatterParams[6] = 1
	} else {
		inputBuffer.FsParameters.RefsFormatterParams[6] = 0
	}
	// Write the MajorVersion (2 bytes)
	binary.LittleEndian.PutUint16(inputBuffer.FsParameters.RefsFormatterParams[8:], refsParameters.MajorVersion)
	// Write the MinorVersion (2 bytes)
	binary.LittleEndian.PutUint16(inputBuffer.FsParameters.RefsFormatterParams[10:], refsParameters.MinorVersion)

	// TODO(kiashok): This can be cleaned up
	for i := 12; i < 128; i++ {
		inputBuffer.FsParameters.RefsFormatterParams[i] = 0 // Padding with 0s
	}

	// Finally write the diskPathLength and diskPathBuffer with the input disk path
	inputBuffer.DiskPathLength = wcharDiskPathLength
	// DiskBuffer writing
	ptr := unsafe.Pointer(uintptr(unsafe.Pointer(inputBuffer)) + uintptr(getInputBufferDiskPathBufferOffset()))
	// Convert the string to UTF-16 slice
	utf16Array := utf16.Encode([]rune(diskPath))
	for _, val := range utf16Array {
		*(*uint16)(ptr) = val
		ptr = unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + uintptr(2))
	}

	return inputBuffer
}
