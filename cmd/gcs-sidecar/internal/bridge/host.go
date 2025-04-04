//go:build windows
// +build windows

package bridge

import (
	"context"
	"errors"
	"fmt"
	"github.com/Microsoft/hcsshim/internal/cow"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"sync"
	"time"

	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
	"github.com/Microsoft/hcsshim/pkg/securitypolicy"
	"github.com/opencontainers/runtime-spec/specs-go"
)

type Host struct {
	containersMutex sync.Mutex
	containers      map[string]*Container

	// state required for the security policy enforcement
	policyMutex               sync.Mutex
	securityPolicyEnforcer    securitypolicy.SecurityPolicyEnforcer
	securityPolicyEnforcerSet bool
	uvmReferenceInfo          string
}

type SecurityPoliyEnforcer struct {
	// State required for the security policy enforcement
	policyMutex               sync.Mutex
	securityPolicyEnforcer    securitypolicy.SecurityPolicyEnforcer
	securityPolicyEnforcerSet bool
	uvmReferenceInfo          string
}

func NewHost(initialEnforcer securitypolicy.SecurityPolicyEnforcer) *Host {
	return &Host{
		containers:                make(map[string]*Container),
		securityPolicyEnforcer:    initialEnforcer,
		securityPolicyEnforcerSet: false,
	}
}

func (h *Host) isSecurityPolicyEnforcerInitialized() bool {
	return h.securityPolicyEnforcer != nil
}

func (h *Host) SetWCOWConfidentialUVMOptions(securityPolicyRequest *guestresource.WCOWConfidentialOptions) error {
	h.policyMutex.Lock()
	defer h.policyMutex.Unlock()

	if h.securityPolicyEnforcerSet {
		return errors.New("security policy has already been set")
	}

	// this limit ensures messages are below the character truncation limit that
	// can be imposed by an orchestrator
	maxErrorMessageLength := 3 * 1024

	// Initialize security policy enforcer for a given enforcer type and
	// encoded security policy.
	p, err := securitypolicy.CreateSecurityPolicyEnforcer(
		"rego",
		securityPolicyRequest.EncodedSecurityPolicy,
		DefaultCRIMounts(),
		DefaultCRIPrivilegedMounts(),
		maxErrorMessageLength,
	)
	if err != nil {
		return fmt.Errorf("error creating security policy enforcer: %v", err)
	}

	// TODO(kiashok): logging for c-wcow?

	// This is one of two points at which we might change our logging.
	// At this time, we now have a policy and can determine what the policy
	// author put as policy around runtime logging.
	// The other point is on startup where we take a flag to set the default
	// policy enforcer to use before a policy arrives. After that flag is set,
	// we use the enforcer in question to set up logging as well.
	/*var ctx context.Context
	if err = p.EnforceRuntimeLoggingPolicy(ctx); err == nil {
		// TODO: enable OTL logging
		//logrus.SetOutput(h.logWriter)
	} else {
		// TODO: disable OTL logging
		//logrus.SetOutput(io.Discard)
	}*/

	// TODO: Use PSP driver attestation API and enable this
	/*
		hostData, err := securitypolicy.NewSecurityPolicyDigest(securityPolicyRequest.EncodedSecurityPolicy)
		if err != nil {
			return err
		}
		if err := validateHostData(hostData[:]); err != nil {
			return err
		}*/

	h.securityPolicyEnforcer = p
	h.securityPolicyEnforcerSet = true

	// TODO(kiashok): Update the following
	// s.uvmReferenceInfo = s.EncodedUVMReference

	return nil
}

func (h *Host) CreateContainer(ctx context.Context, containerID string, spec *specs.Spec) (*Container, error) {
	h.containersMutex.Lock()
	defer h.containersMutex.Unlock()

	if _, ok := h.containers[containerID]; ok {
		return nil, NewHresultError(HrVmcomputeSystemAlreadyExists)
	}

	container, err := NewContainer(containerID, spec)
	if err != nil {
		return nil, err
	}

	h.containers[container.ID()] = container

	return container, nil
}

func (h *Host) StartContainer(ctx context.Context, containerID string) error {
	c, err := h.GetCreatedContainer(containerID)
	if err != nil {
		return err
	}

	return c.Start(ctx)
}

func (h *Host) ModifyContainer(ctx context.Context, containerID string, config interface{}) error {
	c, err := h.GetCreatedContainer(containerID)
	if err != nil {
		return err
	}

	return c.Modify(ctx, config)
}

func (h *Host) StartProcess(ctx context.Context, containerID string, params *hcsschema.ProcessParameters) (cow.Process, error) {
	c, err := h.GetCreatedContainer(containerID)
	if err != nil {
		return nil, err
	}

	process, err := c.CreateProcess(ctx, params)
	if err != nil {
		return nil, err
	}

	return process, nil
}

func (h *Host) WaitOnProcess(containerID string, processID uint32, timeoutInMS uint32) (uint32, error) {
	c, err := h.GetCreatedContainer(containerID)
	if err != nil {
		return 1, err
	}

	process, err := c.GetProcess(processID)
	if err != nil {
		return 1, err
	}

	// Create the timer.
	var tc <-chan time.Time
	if timeoutInMS != InfiniteWaitTimeout {
		t := time.NewTimer(time.Duration(timeoutInMS) * time.Millisecond)
		defer t.Stop()
		tc = t.C
	}

	// Wait on the process to exit.
	done := make(chan error, 1)
	go func() {
		done <- process.Wait()
	}()

	select {
	case err = <-done:
		exitCode, err := process.ExitCode()
		if err != nil {
			return 1, err
		}
		return uint32(exitCode), nil
	case <-tc:
		return 1, NewHresultError(HvVmcomputeTimeout)
	}
}

func (h *Host) SignalContainerProcess(ctx context.Context, containerID string, processID uint32, options interface{}) error {
	c, err := h.GetCreatedContainer(containerID)
	if err != nil {
		return err
	}

	process, err := c.GetProcess(processID)
	if err != nil {
		return err
	}

	signalingInitProcess := processID == uint32(c.initProcess.Pid())
	// Don't allow signalProcessV2 to route around container shutdown policy
	if signalingInitProcess {
		return h.ShutdownContainer(ctx, containerID)
	}
	_, err = process.Signal(ctx, options)
	return err
}

func (h *Host) ResizeConsole(ctx context.Context, containerID string, processID uint32, width, height uint16) error {
	c, err := h.GetCreatedContainer(containerID)
	if err != nil {
		return err
	}

	p, err := c.GetProcess(processID)
	if err != nil {
		return err
	}

	if err = p.ResizeConsole(ctx, width, height); err != nil {
		return err
	}

	return nil
}

func (h *Host) ShutdownContainer(ctx context.Context, containerID string) error {
	c, err := h.GetCreatedContainer(containerID)
	if err != nil {
		return err
	}

	return c.Shutdown(ctx)
}

func (h *Host) TerminateContainer(ctx context.Context, containerID string) error {
	c, err := h.GetCreatedContainer(containerID)
	if err != nil {
		return err
	}

	return c.Terminate(ctx)
}

//func (h *Host) GetProperties(ctx context.Context, containerID string) error {
//	h.containersMutex.Lock()
//	defer h.containersMutex.Unlock()
//
//	c, ok := h.containers[containerID]
//	if !ok {
//		return NewHresultError(HrVmcomputeSystemNotFound)
//	}
//
//	c.PropertiesV2(ctx)
//}

func (h *Host) GetCreatedContainer(containerID string) (*Container, error) {
	h.containersMutex.Lock()
	defer h.containersMutex.Unlock()

	c, ok := h.containers[containerID]
	if !ok {
		return nil, NewHresultError(HrVmcomputeSystemNotFound)
	}

	return c, nil
}

func (h *Host) IsManagedContainer(containerID string) bool {
	h.containersMutex.Lock()
	defer h.containersMutex.Unlock()

	_, ok := h.containers[containerID]
	return ok
}
