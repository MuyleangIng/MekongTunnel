//go:build !windows

package main

import (
	"os"
	"os/exec"
	"syscall"
)

// detachProcess sets Unix-specific process attributes to detach the child
// from the controlling terminal (new session via Setsid).
func detachProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

// isPIDAlive returns true if the process with the given PID is still running.
// Uses signal 0 which checks liveness without sending an actual signal.
func isPIDAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}
