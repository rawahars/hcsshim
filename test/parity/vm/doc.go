//go:build windows

// Package vmparity validates that the v2 modular VM document builders produce
// HCS ComputeSystem documents equivalent to the legacy shim pipelines.
//
// Currently covers LCOW; WCOW parity will be added in a future PR.
package vmparity
