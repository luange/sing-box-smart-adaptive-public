# Adaptive/eBPF policy library

Smart-group selection, health, pinning, probes, and dial-result transitions are
implemented in Go in `protocol/group/smart.go`. This directory no longer
contains or exports a Zig Smart policy. The Go Smart runtime is the only Smart
policy owner in development and production builds.

The Zig library retained here implements the separate AdaptivePool/eBPF
ordering kernel in `src/adaptive.zig`. The sing-box Go adapter supplies
candidate evidence, pin/lease state, and lifecycle events through the C ABI in
`include/smart_engine.h`; Zig does not perform network I/O or maintain Smart
health state. The historical `libsmart_engine.a` filename is retained for
build compatibility, but the ABI exposes adaptive/eBPF functions only.

Run tests and build the static library with Zig 0.14+:

```sh
zig build test -Dcpu=baseline
zig build -Dcpu=baseline -Doptimize=ReleaseFast
```

Release artifacts use the portable baseline CPU profile. The `adaptive_zig`
build tag selects only the adaptive/eBPF adapter. The legacy `smart_zig` tag is
accepted as an alias for existing deployment scripts; neither tag selects or
alters Smart-group behavior. Smart regression tests always exercise the same
Go implementation used in production.
