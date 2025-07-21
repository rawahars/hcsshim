package ctrdpub

import (
	"context"
	"fmt"

	"github.com/Microsoft/hcsshim/internal/oc"
	"github.com/containerd/containerd/namespaces"
	shim "github.com/containerd/containerd/runtime/v2/shim"
	"go.opencensus.io/trace"
)

type Publisher struct {
	namespace       string
	remotePublisher *shim.RemoteEventsPublisher
}

func NewPublisher(address, namespace string) (*Publisher, error) {
	p, err := shim.NewPublisher(address)
	if err != nil {
		return nil, err
	}
	return &Publisher{
		namespace:       namespace,
		remotePublisher: p,
	}, nil
}

func (p *Publisher) PublishEvent(ctx context.Context, topic string, event interface{}) (err error) {
	ctx, span := oc.StartSpan(ctx, "publishEvent")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()
	span.AddAttributes(
		trace.StringAttribute("topic", topic),
		trace.StringAttribute("event", fmt.Sprintf("%+v", event)))

	if p == nil {
		return nil
	}

	return p.remotePublisher.Publish(namespaces.WithNamespace(ctx, p.namespace), topic, event)
}
