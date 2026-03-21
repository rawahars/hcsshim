//go:build windows

package vmutils

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	runhcsoptions "github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/options"
	"github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/stats"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/log"

	"github.com/containerd/typeurl/v2"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ParseUVMReferenceInfo reads the UVM reference info file, and base64 encodes the content if it exists.
func ParseUVMReferenceInfo(ctx context.Context, referenceRoot, referenceName string) (string, error) {
	if referenceName == "" {
		return "", nil
	}

	fullFilePath := filepath.Join(referenceRoot, referenceName)
	content, err := os.ReadFile(fullFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.G(ctx).WithField("filePath", fullFilePath).Debug("UVM reference info file not found")
			return "", nil
		}
		return "", fmt.Errorf("failed to read UVM reference info file: %w", err)
	}

	return base64.StdEncoding.EncodeToString(content), nil
}

// UnmarshalRuntimeOptions decodes the runtime options into runhcsoptions.Options.
// When no options are provided (options == nil) it returns a non-nil,
// zero-value Options struct.
func UnmarshalRuntimeOptions(ctx context.Context, options *anypb.Any) (*runhcsoptions.Options, error) {
	opts := &runhcsoptions.Options{}
	if options == nil {
		return opts, nil
	}

	v, err := typeurl.UnmarshalAny(options)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal options: %w", err)
	}

	shimOpts, ok := v.(*runhcsoptions.Options)
	if !ok {
		return nil, fmt.Errorf("failed to unmarshal runtime options: expected *runhcsoptions.Options, got %T", v)
	}

	if entry := log.G(ctx); entry.Logger.IsLevelEnabled(logrus.DebugLevel) {
		entry.WithField("options", log.Format(ctx, shimOpts)).Debug("parsed runtime options")
	}

	return shimOpts, nil
}

func ConvertHcsPropertiesToWindowsStats(props *hcsschema.Properties) *stats.Statistics_Windows {
	wcs := &stats.Statistics_Windows{Windows: &stats.WindowsContainerStatistics{}}
	if props.Statistics != nil {
		wcs.Windows.Timestamp = timestamppb.New(props.Statistics.Timestamp)
		wcs.Windows.ContainerStartTime = timestamppb.New(props.Statistics.ContainerStartTime)
		wcs.Windows.UptimeNS = props.Statistics.Uptime100ns * 100
		if props.Statistics.Processor != nil {
			wcs.Windows.Processor = &stats.WindowsContainerProcessorStatistics{
				TotalRuntimeNS:  props.Statistics.Processor.TotalRuntime100ns * 100,
				RuntimeUserNS:   props.Statistics.Processor.RuntimeUser100ns * 100,
				RuntimeKernelNS: props.Statistics.Processor.RuntimeKernel100ns * 100,
			}
		}
		if props.Statistics.Memory != nil {
			wcs.Windows.Memory = &stats.WindowsContainerMemoryStatistics{
				MemoryUsageCommitBytes:            props.Statistics.Memory.MemoryUsageCommitBytes,
				MemoryUsageCommitPeakBytes:        props.Statistics.Memory.MemoryUsageCommitPeakBytes,
				MemoryUsagePrivateWorkingSetBytes: props.Statistics.Memory.MemoryUsagePrivateWorkingSetBytes,
			}
		}
		if props.Statistics.Storage != nil {
			wcs.Windows.Storage = &stats.WindowsContainerStorageStatistics{
				ReadCountNormalized:  props.Statistics.Storage.ReadCountNormalized,
				ReadSizeBytes:        props.Statistics.Storage.ReadSizeBytes,
				WriteCountNormalized: props.Statistics.Storage.WriteCountNormalized,
				WriteSizeBytes:       props.Statistics.Storage.WriteSizeBytes,
			}
		}
	}
	return wcs
}

// GenerateID generates a random unique id.
// Forked from https://github.com/containerd/containerd/blob/b0d7bba94f0bfe45de68fc7d98b4d203ae72d30a/internal/cri/util/id.go#L25
func GenerateID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}
