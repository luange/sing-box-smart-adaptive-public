//go:build !linux

package clashapi

func readPrivateProcessMetrics() privateProcessMetrics {
	return privateProcessMetrics{State: "unsupported", Diagnostic: "当前核心平台没有接入经过验证的 RSS/进程 CPU 采样器"}
}
