#!/usr/bin/env bash
# Cross-build official-smart-ebpf matrix (run on Linux builder).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
VERSION="${VERSION:-1.14.0-beta.17-official-smart-ebpf}"
OUT="${OUT:-$HOME/Desktop/sing-box-official-smart-ebpf}"
TAGS_BASE="$(tr -d ' \n' <"$ROOT/release/DEFAULT_BUILD_TAGS_OTHERS")"
TAGS="${TAGS_BASE},with_ebpf,smart_zig,production_smart"
mkdir -p "$OUT"
echo "VERSION=$VERSION TAGS=$TAGS OUT=$OUT"
make -C common/ebpf generate
export CGO_ENABLED=1
case "$(go env GOARCH)" in
  amd64) ZIG_TARGET=x86_64-linux-gnu ;;
  arm64) ZIG_TARGET=aarch64-linux-gnu ;;
  *) echo "unsupported Linux host architecture for smart_zig: $(go env GOARCH)" >&2; exit 1 ;;
esac
(
  cd "$ROOT/smart-engine"
  zig build -Dtarget="$ZIG_TARGET" -Dcpu=baseline -Doptimize=ReleaseFast
)
test -s "$ROOT/smart-engine/zig-out/lib/libsmart_engine.a"
build_one() {
  local goarch="$1" libc="$2"
  local dest="$OUT/linux-${goarch}-${libc}"
  mkdir -p "$dest"
  echo "==> $goarch $libc"
  GOOS=linux GOARCH="$goarch" go build -tags "$TAGS" \
    -ldflags "-checklinkname=0 -X github.com/sagernet/sing-box/constant.Version=${VERSION} -s -w" \
    -o "$dest/sing-box" ./cmd/sing-box
  (cd "$dest" && sha256sum sing-box > SHA256SUMS)
  ls -la "$dest/sing-box"
}
# default: host arch glibc dynamic (builder)
build_one "$(go env GOARCH)" glibc
echo "done: $OUT"
