//go:build windows

package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "task"
	app.Commands = []cli.Command{
		// Core
		stateCommand,
		createCommand,
		startCommand,
		deleteCommand,
		pidsCommand,
		killCommand,
		execCommand,
		closeIOCommand,
		waitCommand,
		connectCommand,
		shutdownCommand,
		// Extra
		ioCommand,
		eventsCommand,
	}
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
