//go:build windows
// +build windows

package bridge

import (
	"errors"
	"fmt"
	"sync"

	"github.com/Microsoft/hcsshim/internal/cow"
	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
	"github.com/Microsoft/hcsshim/pkg/securitypolicy"
)

type Host struct {
	containersMutex sync.Mutex
	containers      map[string]cow.Container

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
