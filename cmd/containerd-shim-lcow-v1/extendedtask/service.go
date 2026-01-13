//go:build windows

package shimdiag

import (
	"context"

	"github.com/Microsoft/hcsshim/internal/extendedtask"
)

type service struct{}

var _ extendedtask.ExtendedTaskService = &service{}

func (s service) ComputeProcessorInfo(ctx context.Context, request *extendedtask.ComputeProcessorInfoRequest) (*extendedtask.ComputeProcessorInfoResponse, error) {
	//TODO implement me
	panic("implement me")
}
