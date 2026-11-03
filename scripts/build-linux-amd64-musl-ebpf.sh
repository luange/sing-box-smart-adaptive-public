#!/usr/bin/env bash
# Build the one portable production core for Linux/amd64 gateways.
#
# The result is linked against musl with Alpine's standard dynamic loader.
# This avoids Debian's glibc-only static libgcc unwinder while remaining an
# Alpine-native linux/amd64 artifact. Linux UAPI headers are needed only while
# compiling the embedded eBPF C glue; keep them after musl's own headers so
# libc headers are never mixed across toolchains.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

cc="${CC:-musl-gcc}"
extldflags="-Wl,-dynamic-linker,/lib/ld-musl-x86_64.so.1"
# Debian's musl-gcc wrapper still imports glibc's libgcc unwinder for this
# CGO-heavy build. Set ZIG_BIN to a verified Zig executable to use its
# self-contained x86_64-linux-musl toolchain for Go and embedded eBPF glue.
if [[ -n "${ZIG_BIN:-}" ]]; then
	cc="$root/scripts/zig-musl-cc.sh"
	extldflags+=" -lgcc_s"
fi
command -v "$cc" >/dev/null || { echo "missing musl C compiler: $cc" >&2; exit 1; }
command -v clang >/dev/null || { echo "missing clang for eBPF objects" >&2; exit 1; }

multiarch="$($cc -print-multiarch 2>/dev/null || true)"
uapi_flags="-idirafter /usr/include"
if [[ -n "$multiarch" && -d "/usr/include/$multiarch" ]]; then
  uapi_flags+=" -idirafter /usr/include/$multiarch"
fi

version="${VERSION:-1.15.0-smart}"
revision="${REVISION:-$(git rev-parse HEAD)}"
out="${OUT:-$root/dist/sing-box-linux-amd64-musl-ebpf}"
build_tmpdir="${BUILD_TMPDIR:-$root/.build-tmp}"
tags="with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_connection_history,with_tailscale,with_ccm,with_ocm,with_cloudflared,with_usbip,with_openvpn,with_openconnect,badlinkname,tfogo_checklinkname0,with_ebpf,production_smart,with_musl"

# Go's default /tmp can be a deliberately small tmpfs on build VMs.  The
# linker needs more space than such a tmpfs provides, so keep its transient
# work tree beside the source on the persistent build volume and remove it on
# either success or failure.
rm -rf "$build_tmpdir"
mkdir -p "$build_tmpdir"
trap 'rm -rf "$build_tmpdir"' EXIT

make -C common/ebpf generate
mkdir -p "$(dirname "$out")"

# Zig's C frontend enables safety instrumentation at its default debug
# optimisation level.  CGO then reaches the final link without Zig's UBSan
# runtime, which leaves __ubsan_handle_* unresolved.  Explicit release C
# flags make the C object policy match Go's production build and work with
# both Zig and musl-gcc.
TMPDIR="$build_tmpdir" GOMAXPROCS="${GOMAXPROCS:-1}" \
GOOS=linux GOARCH=amd64 CGO_ENABLED=1 CC="$cc" CGO_CFLAGS="-O2 -DNDEBUG $uapi_flags" \
go build -p 1 -trimpath -tags "$tags" \
	-buildvcs=true \
  -ldflags "-X github.com/sagernet/sing-box/constant.Version=$version -X github.com/sagernet/sing-box/constant.Revision=$revision -checklinkname=0 -s -w -buildid= -extldflags '$extldflags'" \
  -o "$out" ./cmd/sing-box

file "$out"
"$out" version
sha256sum "$out"
