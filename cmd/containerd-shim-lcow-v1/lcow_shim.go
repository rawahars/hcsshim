//go:build windows

package main

import (
	"github.com/Microsoft/hcsshim/pkg/shim"
	"github.com/containerd/ttrpc"
	"github.com/urfave/cli"
)

type lcowShim struct{}

var _ shim.Shim = &lcowShim{}

func (l *lcowShim) Name() string {
	return name
}

func (l *lcowShim) RegisterServices(ctx *cli.Context, server *ttrpc.Server, events shim.Publisher) error {
	//TODO implement me
	panic("implement me")
}

func (l *lcowShim) ETW() *shim.ETWConfig {
	//TODO implement me
	panic("implement me")
}

func (l *lcowShim) Done() <-chan struct{} {
	//TODO implement me
	panic("implement me")
}
