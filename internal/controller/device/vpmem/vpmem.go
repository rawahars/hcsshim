//go:build windows

package vpmem

type ControllerCore struct {
}

var _ Controller = (*ControllerCore)(nil)
