//go:build linux

package clashapi

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func readPrivateProcessMetrics() privateProcessMetrics {
	result := privateProcessMetrics{State: "partial"}
	if file, err := os.Open("/proc/self/status"); err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			name, value, found := strings.Cut(scanner.Text(), ":")
			if !found || name != "VmRSS" {
				continue
			}
			fields := strings.Fields(value)
			if len(fields) == 2 && fields[1] == "kB" {
				if kib, parseErr := strconv.ParseUint(fields[0], 10, 64); parseErr == nil && kib <= ^uint64(0)/1024 {
					rss := kib * 1024
					result.RSSBytes = &rss
				}
			}
			break
		}
		_ = file.Close()
	}
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err == nil && usage.Utime.Sec >= 0 && usage.Utime.Usec >= 0 && usage.Stime.Sec >= 0 && usage.Stime.Usec >= 0 {
		user := uint64(usage.Utime.Sec)*1_000_000_000 + uint64(usage.Utime.Usec)*1_000
		system := uint64(usage.Stime.Sec)*1_000_000_000 + uint64(usage.Stime.Usec)*1_000
		result.CPUUserNanoseconds = &user
		result.CPUSystemNanoseconds = &system
	}
	if result.RSSBytes != nil && result.CPUUserNanoseconds != nil && result.CPUSystemNanoseconds != nil {
		result.State = "ready"
		return result
	}
	result.Diagnostic = "Linux /proc 与 getrusage 只返回实际可读的进程指标；缺失项不会以 0 代替"
	return result
}
