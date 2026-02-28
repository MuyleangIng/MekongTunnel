//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// detachProcess sets Windows-specific process attributes.
// DETACHED_PROCESS (0x00000008) frees the child from the parent's console.
func detachProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x00000008, // DETACHED_PROCESS
	}
}

// isPIDAlive returns true if the process with the given PID is still running.
// Uses OpenProcess + GetExitCodeProcess; exit code 259 means STILL_ACTIVE.
func isPIDAlive(pid int) bool {
	handle, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(handle)
	var exitCode uint32
	if err := syscall.GetExitCodeProcess(handle, &exitCode); err != nil {
		return false
	}
	return exitCode == 259 // STILL_ACTIVE
}
