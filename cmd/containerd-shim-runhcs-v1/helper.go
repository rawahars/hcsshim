package main

import (
	"context"

	"github.com/Microsoft/hcsshim/internal/cmd"
	"github.com/Microsoft/hcsshim/internal/shimdiag"
	"github.com/Microsoft/hcsshim/internal/uvm"
)

func execInHost(ctx context.Context, req *shimdiag.ExecProcessRequest, host *uvm.UtilityVM) (int, error) {
	cmdReq := &cmd.CmdProcessRequest{
		Args:     req.Args,
		Workdir:  req.Workdir,
		Terminal: req.Terminal,
		Stdin:    req.Stdin,
		Stdout:   req.Stdout,
		Stderr:   req.Stderr,
	}

	if host == nil {
		return cmd.ExecInShimHost(ctx, cmdReq)
	}
	return cmd.ExecInUvm(ctx, host, cmdReq)
}

func shareOnHost(ctx context.Context, req *shimdiag.ShareRequest, host *uvm.UtilityVM) error {
	return host.Share(ctx, req.HostPath, req.UvmPath, req.ReadOnly)
}
