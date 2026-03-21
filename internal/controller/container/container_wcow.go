//go:build windows && wcow

package container

import (
	"context"

	"github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/stats"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/vm/vmutils"
)

// teardownContainer attempts a graceful shutdown of the container, waiting up
// to containerExitTimeout for it to exit. If shutdown fails or the container
// does not exit in time, it falls back to a forceful terminate.
// Applicable only for WCOW for shutting down the Silo.
func (m *Manager) teardownContainer(ctx context.Context) {
	const containerExitTimeout = 30 * time.Second

	// waitForContainerExit blocks until the container exits or the timeout elapses,
	// returning hcs.ErrTimeout on expiry.
	waitForContainerExit := func() error {
		waitCtx, cancel := context.WithTimeout(ctx, containerExitTimeout)
		defer cancel()
		select {
		case <-m.container.WaitChannel():
			return m.container.WaitError()
		case <-waitCtx.Done():
			return hcs.ErrTimeout
		}
	}

	// Attempt graceful shutdown first.
	var shutdownErr, containerExitErr error
	shutdownErr = m.container.Shutdown(ctx)
	if shutdownErr == nil {
		containerExitErr = waitForContainerExit()
	}
	// Both shutdown and waiting for exit must succeed to avoid a forceful terminate.
	if shutdownErr == nil && containerExitErr == nil {
		return
	}

	log.G(ctx).WithError(shutdownErr).Warn("graceful shutdown failed, falling back to terminate")

	// Fallback: forceful termination.
	if err := m.container.Terminate(ctx); err != nil {
		log.G(ctx).WithError(err).Error("failed to terminate container")
		return
	}
	if err := waitForContainerExit(); err != nil {
		log.G(ctx).WithError(err).Error("container did not exit after terminate")
	}
}

func parseContainerStats(props *hcsschema.Properties) *stats.Statistics_Windows {
	return vmutils.ConvertHcsPropertiesToWindowsStats(props)
}

func (m *Manager) updateContainerResources(_ context.Context, _ interface{}) error {
	// Todo: Placeholder for future implementation of WCOW workflows.
	return nil
}
