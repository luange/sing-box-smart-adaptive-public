//go:build !smart_zig || !cgo

package adaptive

func newAdaptivePolicyKernel() policyKernel { return nil }
