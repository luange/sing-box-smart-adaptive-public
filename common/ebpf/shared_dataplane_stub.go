//go:build !cgo || !(with_ebpf && (linux || android))

package ebpf

// Placeholder so non-cgo packages that only import option/protocol compile.
// Real SharedDataplane lives in shared_dataplane.go under cgo+linux.
