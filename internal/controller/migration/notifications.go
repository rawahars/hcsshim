//go:build windows && lcow

package migration

import (
	"context"
	"sync"

	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/pkg/migration"

	"github.com/sirupsen/logrus"
)

// defaultSubscriberBuffer is the per-subscriber channel buffer used by the
// notifier. Notifications produced faster than a subscriber can drain are
// dropped to avoid blocking the producer.
const defaultSubscriberBuffer = 64

// notifier is a small fan-out for migration progress notifications.
//
// The producer (driven by the HCS migration callback once Transfer is wired
// up) calls publish; subscribers obtained via subscribe receive a copy of
// every subsequent notification on a bounded channel. close terminates all
// outstanding subscriptions and prevents further publish calls.
type notifier struct {
	mu sync.Mutex

	// nextMessageID is the per-stream monotonic counter assigned to outgoing
	// notifications. Guarded by mu.
	nextMessageID uint32

	// subscribers is the set of live subscribers for the current session.
	// Guarded by mu.
	subscribers map[*subscription]struct{}

	// closed is true once the notifier has been shut down. No further
	// publishes or subscribes are accepted in that state. Guarded by mu.
	closed bool
}

// subscription is a single in-flight subscription to the notifier.
type subscription struct {
	ch chan *migration.NotificationsResponse
}

// newNotifier returns a ready-to-use notifier with no active subscribers.
func newNotifier() *notifier {
	return &notifier{
		subscribers: make(map[*subscription]struct{}),
	}
}

// subscribe registers a new subscriber and returns the receive channel along
// with a cancel function that the caller must invoke to release resources.
//
// Returns false if the notifier has already been closed; in that case the
// channel is nil.
func (n *notifier) subscribe() (<-chan *migration.NotificationsResponse, func(), bool) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.closed {
		return nil, func() {}, false
	}

	sub := &subscription{
		ch: make(chan *migration.NotificationsResponse, defaultSubscriberBuffer),
	}
	n.subscribers[sub] = struct{}{}

	cancel := func() {
		n.mu.Lock()
		defer n.mu.Unlock()
		// Idempotent: only act if the subscription is still tracked.
		if _, ok := n.subscribers[sub]; !ok {
			return
		}
		delete(n.subscribers, sub)
		close(sub.ch)
	}
	return sub.ch, cancel, true
}

// publish assigns a message ID, stamps the response, and fans the
// notification out to every live subscriber. Slow subscribers drop the
// message rather than blocking the producer.
func (n *notifier) publish(ctx context.Context, resp *migration.NotificationsResponse) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.closed {
		return
	}

	n.nextMessageID++
	resp.MessageID = n.nextMessageID

	for sub := range n.subscribers {
		select {
		case sub.ch <- resp:
		default:
			// Subscriber is too slow; drop and warn. The next reconnect can
			// re-derive ordering from MessageID.
			log.G(ctx).WithFields(logrus.Fields{
				"message_id": resp.MessageID,
			}).Warn("dropping migration notification: subscriber buffer full")
		}
	}
}

// close terminates the notifier and releases all subscribers. After close
// returns, subscribe returns false and publish becomes a no-op.
func (n *notifier) close() {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.closed {
		return
	}
	n.closed = true
	for sub := range n.subscribers {
		close(sub.ch)
	}
	n.subscribers = nil
}

// publishProgress is the seam used by the (yet-to-be-wired) HCS migration
// callback to push a progress notification through the controller's notifier.
//
//nolint:unused // wired in once HCS Transfer integration lands.
func (c *Controller) publishProgress(ctx context.Context, n *migration.Notification) {
	c.notifier.publish(ctx, &migration.NotificationsResponse{
		Notification: n,
	})
}
