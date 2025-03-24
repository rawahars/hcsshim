//go:build windows
// +build windows

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/Microsoft/hcsshim/internal/fsformatter"
	"github.com/Microsoft/hcsshim/internal/windevice"
)

func main() {
	args := os.Args

	if len(args) == 1 || len(args) > 3 {
		fmt.Println("controller and lun not provided")
		return
	}

	// Testing in local VM: controller 0 and lun 1
	controller := 0
	lun := 0
	for i, arg := range args[1:] {
		if i == 0 {
			controller, _ = strconv.Atoi(arg)
		} else if i == 1 {
			lun, _ = strconv.Atoi(arg)
		}
	}

	fmt.Printf("Controller: %d, Lun: %d \n", controller, lun)

	ctx := context.Background()
	devPath, diskNumber, err := windevice.GetScsiDevicePathAndDiskNumberFromControllerLUN(
		ctx,
		uint8(controller),
		uint8(lun))

	if err != nil {
		fmt.Printf("error getting diskNumber for LUN %d, err: %v", lun, err)
		return
	}

	fmt.Printf("\n DevicePath: %v DiskNumber: %v \n", devPath, diskNumber)

	diskPath := fmt.Sprintf(fsformatter.VirtualDevObjectPathFormat, diskNumber)
	fmt.Printf("\n Disk path is %v", diskPath)

	mountedVolumePath, err := windevice.InvokeFsFormatter(ctx, diskPath)

	if err != nil {
		fmt.Printf("error invoking formatter %v", err)
	}

	log.Printf("\n mountedVolumePath returned from InvokeFsFormatter: %v", mountedVolumePath)
}
