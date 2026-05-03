//go:build windows && lcow

package migration

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Microsoft/hcsshim/internal/controller/pod"
	"github.com/Microsoft/hcsshim/internal/controller/vm"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/logfields"
	"github.com/Microsoft/hcsshim/pkg/migration"

	"github.com/containerd/errdefs"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

const defaultTransferTimeout = 10 * time.Minute

type Controller struct {
	mu sync.RWMutex

	state State

	sessionID string

	sandboxID string

	origin hcsschema.MigrationOrigin

	// todo: Instead of taking full object, take just the interface.
	vmController *vm.Controller

	podControllers map[string]*pod.Controller

	// pendingPatches is the number of imported containers that still need
	// a NewTask call to patch in destination-local resource paths.
	// Only meaningful when role == RoleDestination.
	// Access must be guarded by mu.
	pendingPatches int

	dupSocket windows.Handle

	// notifier fans HCS-emitted progress notifications out to subscribers.
	// Created lazily per session and torn down on FinalizeSandbox.
	// Access must be guarded by mu.
	notifier *notifier
}

func New() *Controller {
	return &Controller{
		state:    StateIdle,
		notifier: newNotifier(),
	}
}

// State returns the current session state.
func (c *Controller) State() State {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.state
}

func (c *Controller) Transfer(ctx context.Context, sessionID string, timeout time.Duration) error {
	c.mu.Lock()
	c.state = StateTransferring
	c.mu.Unlock()

	if timeout <= 0 {
		timeout = defaultTransferTimeout
	}
	transferCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// TODO(migration): perform the actual HCS Transfer call here using
	// transferCtx and report progress via publishProgress.
	transferErr := c.doTransfer(transferCtx)

	c.mu.Lock()
	defer c.mu.Unlock()
	if transferErr != nil {
		c.state = StateFailed
		log.G(ctx).WithError(transferErr).WithField(logfields.SessionID, sessionID).Error("migration transfer failed")
		return fmt.Errorf("transfer migration session %q: %w", sessionID, transferErr)
	}
	c.state = StateCompleted
	log.G(ctx).WithField(logfields.SessionID, sessionID).Info("migration transfer completed")
	return nil
}

func (c *Controller) Finalize(ctx context.Context, sessionID string, action migration.FinalizeAction) error {
	if action == migration.FinalizeAction_FINALIZE_ACTION_UNSPECIFIED {
		return fmt.Errorf("finalize action must be specified: %w", errdefs.ErrInvalidArgument)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Finalize is permitted from any non-initial, non-terminal state because
	// the orchestrator may legitimately tear a session down at any point
	// after it began (e.g. cancellation between Export and Transfer).
	if c.state == StateIdle || c.state == StateTerminal {
		return fmt.Errorf("finalize not valid in state %s: %w", c.state, errdefs.ErrFailedPrecondition)
	}

	// TODO(migration): branch on (c.role, action) and run the
	// corresponding HCS teardown or resume path.

	if c.dupSocket != 0 {
		if err := windows.Closesocket(c.dupSocket); err != nil {
			log.G(ctx).WithError(err).WithField(logfields.SessionID, sessionID).Warn("close duplicate migration socket")
		}
		c.dupSocket = 0
	}

	c.state = StateTerminal
	c.notifier.close()
	log.G(ctx).WithFields(logrus.Fields{
		logfields.SessionID: sessionID,
		logfields.Action:    action.String(),
	}).Info("migration session finalized")
	return nil
}

// Subscribe registers a new subscriber on the Notifications stream for the
// active session. The returned channel emits notifications until the session
// reaches [StateTerminal] or the caller invokes the cancel function.
func (c *Controller) Subscribe(ctx context.Context, sessionID string) (<-chan *migration.NotificationsResponse, func(), error) {
	c.mu.Lock()
	if c.state == StateTerminal {
		c.mu.Unlock()
		return nil, nil, fmt.Errorf("session %q is terminal: %w", sessionID, errdefs.ErrFailedPrecondition)
	}
	c.mu.Unlock()

	ch, cancel, ok := c.notifier.subscribe()
	if !ok {
		return nil, nil, fmt.Errorf("notifier closed for session %q: %w", sessionID, errdefs.ErrFailedPrecondition)
	}
	log.G(ctx).WithField(logfields.SessionID, sessionID).Debug("migration notification subscriber attached")
	return ch, cancel, nil
}

// doTransfer is the seam where the actual HCS-driven memory transfer is
// performed. It currently returns nil so the orchestration layer can be
// exercised end-to-end without HCS.
//
// TODO(migration): replace with the real HCS Transfer call.
func (c *Controller) doTransfer(_ context.Context) error {
	return nil
}
