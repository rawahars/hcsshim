//go:build windows && lcow

// Package linuxcontainer implements the container controller for Linux
// containers on Windows (LCOW). It manages the container lifecycle — creation,
// start, stop, and teardown — by coordinating host-side resource allocations
// (SCSI layers, Plan9 shares, vPCI devices) with the GCS running inside the
// utility VM.
package linuxcontainer
