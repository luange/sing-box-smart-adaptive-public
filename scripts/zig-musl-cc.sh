#!/usr/bin/env sh
set -eu

: "${ZIG_BIN:?set ZIG_BIN to the verified Zig executable}"
exec "$ZIG_BIN" cc -target x86_64-linux-musl "$@"
