// Package system provides server resource monitoring utilities.
package system

import (
	"context"
	"fmt"
	gonet "net"
	"os"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	psnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

// Snapshot is a point-in-time capture of server resources.
type Snapshot struct {
	Timestamp   int64       `json:"ts"`
	CPU         CPUInfo     `json:"cpu"`
	Memory      MemInfo     `json:"memory"`
	Disk        []DiskInfo  `json:"disk"`
	Network     NetInfo     `json:"network"`
	System      SysInfo     `json:"system"`
	TopProcesses []ProcInfo `json:"top_processes"`
}

type CPUInfo struct {
	UsagePercent float64  `json:"usage_percent"` // overall
	PerCore      []float64 `json:"per_core"`
	Cores        int      `json:"cores"`
	ModelName    string   `json:"model_name"`
}

type MemInfo struct {
	TotalBytes     uint64  `json:"total_bytes"`
	UsedBytes      uint64  `json:"used_bytes"`
	FreeBytes      uint64  `json:"free_bytes"`
	UsagePercent   float64 `json:"usage_percent"`
	// Swap
	SwapTotal uint64  `json:"swap_total"`
	SwapUsed  uint64  `json:"swap_used"`
}

type DiskInfo struct {
	Path         string  `json:"path"`
	TotalBytes   uint64  `json:"total_bytes"`
	UsedBytes    uint64  `json:"used_bytes"`
	FreeBytes    uint64  `json:"free_bytes"`
	UsagePercent float64 `json:"usage_percent"`
	Fstype       string  `json:"fstype"`
}

type NetInfo struct {
	BytesSent   uint64      `json:"bytes_sent"`
	BytesRecv   uint64      `json:"bytes_recv"`
	PacketsSent uint64      `json:"packets_sent"`
	PacketsRecv uint64      `json:"packets_recv"`
	Interfaces  []IfaceInfo `json:"interfaces"`
}

type IfaceInfo struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
	BytesSent uint64   `json:"bytes_sent"`
	BytesRecv uint64   `json:"bytes_recv"`
}

type SysInfo struct {
	Hostname        string `json:"hostname"`
	OS              string `json:"os"`
	Platform        string `json:"platform"`
	PlatformVersion string `json:"platform_version"`
	KernelVersion   string `json:"kernel_version"`
	Arch            string `json:"arch"`
	UptimeSeconds   uint64 `json:"uptime_seconds"`
	BootTime        uint64 `json:"boot_time"`
	GoVersion       string `json:"go_version"`
	PID             int    `json:"pid"`
	CloudProvider   string `json:"cloud_provider"` // aws/gcp/azure/hetzner/local/unknown
}

type ProcInfo struct {
	PID         int32   `json:"pid"`
	Name        string  `json:"name"`
	CPUPercent  float64 `json:"cpu_percent"`
	MemPercent  float32 `json:"mem_percent"`
	MemRSSBytes uint64  `json:"mem_rss_bytes"`
	Status      string  `json:"status"`
}

// Collect gathers all metrics and returns a snapshot.
func Collect(ctx context.Context) (*Snapshot, error) {
	snap := &Snapshot{Timestamp: time.Now().UnixMilli()}

	// ── CPU ─────────────────────────────────────────────────────
	overall, _ := cpu.PercentWithContext(ctx, 200*time.Millisecond, false)
	perCore, _ := cpu.PercentWithContext(ctx, 0, true)
	infos, _   := cpu.InfoWithContext(ctx)
	model := ""
	if len(infos) > 0 {
		model = infos[0].ModelName
	}
	snap.CPU = CPUInfo{
		Cores:     runtime.NumCPU(),
		ModelName: model,
		PerCore:   perCore,
	}
	if len(overall) > 0 {
		snap.CPU.UsagePercent = overall[0]
	}

	// ── Memory ──────────────────────────────────────────────────
	vm, err := mem.VirtualMemoryWithContext(ctx)
	if err == nil {
		snap.Memory = MemInfo{
			TotalBytes:   vm.Total,
			UsedBytes:    vm.Used,
			FreeBytes:    vm.Free,
			UsagePercent: vm.UsedPercent,
		}
	}
	sw, _ := mem.SwapMemoryWithContext(ctx)
	if sw != nil {
		snap.Memory.SwapTotal = sw.Total
		snap.Memory.SwapUsed  = sw.Used
	}

	// ── Disk ────────────────────────────────────────────────────
	parts, _ := disk.PartitionsWithContext(ctx, false)
	for _, p := range parts {
		u, err := disk.UsageWithContext(ctx, p.Mountpoint)
		if err != nil { continue }
		snap.Disk = append(snap.Disk, DiskInfo{
			Path:         p.Mountpoint,
			TotalBytes:   u.Total,
			UsedBytes:    u.Used,
			FreeBytes:    u.Free,
			UsagePercent: u.UsedPercent,
			Fstype:       p.Fstype,
		})
	}

	// ── Network ─────────────────────────────────────────────────
	iocounters, _ := psnet.IOCountersWithContext(ctx, true)
	totals, _    := psnet.IOCountersWithContext(ctx, false)
	ifaces, _    := psnet.InterfacesWithContext(ctx)
	counterMap   := map[string]psnet.IOCountersStat{}
	for _, c := range iocounters { counterMap[c.Name] = c }

	var ifaceList []IfaceInfo
	for _, iface := range ifaces {
		c := counterMap[iface.Name]
		addrs := make([]string, 0, len(iface.Addrs))
		for _, a := range iface.Addrs { addrs = append(addrs, a.Addr) }
		ifaceList = append(ifaceList, IfaceInfo{
			Name:      iface.Name,
			Addresses: addrs,
			BytesSent: c.BytesSent,
			BytesRecv: c.BytesRecv,
		})
	}
	netInfo := NetInfo{Interfaces: ifaceList}
	if len(totals) > 0 {
		netInfo.BytesSent   = totals[0].BytesSent
		netInfo.BytesRecv   = totals[0].BytesRecv
		netInfo.PacketsSent = totals[0].PacketsSent
		netInfo.PacketsRecv = totals[0].PacketsRecv
	}
	snap.Network = netInfo

	// ── System info ─────────────────────────────────────────────
	hi, _ := host.InfoWithContext(ctx)
	if hi != nil {
		snap.System = SysInfo{
			Hostname:        hi.Hostname,
			OS:              hi.OS,
			Platform:        hi.Platform,
			PlatformVersion: hi.PlatformVersion,
			KernelVersion:   hi.KernelVersion,
			Arch:            hi.KernelArch,
			UptimeSeconds:   hi.Uptime,
			BootTime:        hi.BootTime,
			GoVersion:       runtime.Version(),
			PID:             os.Getpid(),
			CloudProvider:   detectCloud(),
		}
	}

	// ── Top 10 processes by CPU ──────────────────────────────────
	procs, _ := process.ProcessesWithContext(ctx)
	var topProcs []ProcInfo
	for _, p := range procs {
		cpu, _ := p.CPUPercentWithContext(ctx)
		mem, _ := p.MemoryPercentWithContext(ctx)
		mi, _  := p.MemoryInfoWithContext(ctx)
		name, _ := p.NameWithContext(ctx)
		st, _  := p.StatusWithContext(ctx)
		status := "?"
		if len(st) > 0 { status = st[0] }
		var rss uint64
		if mi != nil { rss = mi.RSS }
		if cpu < 0.01 && mem < 0.01 { continue }
		topProcs = append(topProcs, ProcInfo{
			PID: p.Pid, Name: name,
			CPUPercent: cpu, MemPercent: mem,
			MemRSSBytes: rss, Status: status,
		})
	}
	// Sort descending by CPU
	for i := 0; i < len(topProcs); i++ {
		for j := i + 1; j < len(topProcs); j++ {
			if topProcs[j].CPUPercent > topProcs[i].CPUPercent {
				topProcs[i], topProcs[j] = topProcs[j], topProcs[i]
			}
		}
	}
	if len(topProcs) > 15 { topProcs = topProcs[:15] }
	snap.TopProcesses = topProcs

	return snap, nil
}

// detectCloud tries to identify the cloud provider from well-known metadata endpoints or hostname patterns.
func detectCloud() string {
	checks := []struct {
		name string
		host string
		port string
	}{
		{"aws",    "169.254.169.254", "80"},
		{"gcp",    "metadata.google.internal", "80"},
		{"azure",  "169.254.169.254", "80"},  // azure uses same APIPA but responds differently
		{"hetzner","169.254.0.1", "80"},
	}
	for _, c := range checks {
		conn, err := gonet.DialTimeout("tcp", fmt.Sprintf("%s:%s", c.host, c.port), 300*time.Millisecond)
		if err == nil {
			conn.Close()
			// Check AWS vs Azure: AWS returns unique headers but quick check is sufficient for display
			return c.name
		}
	}
	hostname, _ := os.Hostname()
	switch {
	case len(hostname) > 3 && hostname[:3] == "ip-":
		return "aws"
	default:
		return "local"
	}
}
