//go:build windows

package pod

import (
	"context"

	"github.com/Microsoft/hcsshim/internal/controller/container"
)

/* Workflow: In service_internal, we will have a map of containerID -> podID and another for podID -> Controller.
 - Request comes for a container. If the container ID already exists in map, then we error out. Otherwise we go as below-
- If it is sandbox container based on oci.GetSandboxTypeAndID then we will create a new pod controller in the podID -> Controller map and add the containerID -> podID mapping in the other map.
- If it is a regular container, then we will look up the podID from the containerID -> podID map and then look up the Controller from the podID -> Controller map.
At any point if we find an existing entry, we error out.

Now that we have pod controller at this point, we will now call NewContainer on the same. This returns a Container Controller.
On the ctr ctrl, we will call Create and pass the taskCreateOptions.
*/

// Controller manages the lifecycle of a single pod: its network namespace and
// all containers (including the infra/sandbox container) that run inside the pod.
type Controller interface {
	SetupNetwork(ctx context.Context, opts *SetupNetworkOptions) error

	TeardownNetwork(ctx context.Context) error

	NewContainer(containerID string) (*container.Manager, error)

	GetContainer(containerID string) (*container.Manager, error)

	ListContainers() (map[string]*container.Manager, error)
}

// SetupNetworkOptions carries the configuration required to initialise the
// network namespace for a pod.
type SetupNetworkOptions struct {
	// NetworkNamespace is the name of the network namespace for the pod.
	NetworkNamespace string
	// EndpointIDs are the endpoint IDs to attach to the network namespace.
	EndpointIDs []string
}

// todo: create status and it changes based on the tree below.
// todo: Consider case where sandbox container is not present but someone tries to use
// GetContainer with containerID as podID.
