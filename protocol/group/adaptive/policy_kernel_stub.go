//go:build !(adaptive_zig || smart_zig) || !cgo

package adaptive

func newAdaptivePolicyKernel() policyKernel { return nil }
