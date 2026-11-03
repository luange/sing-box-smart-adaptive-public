#!/usr/bin/env bash
# The source-level Smart gate, intentionally small enough for CI and the NAS
# mirror. Integration/eBPF gates remain opt-in on the privileged build host.
set -euo pipefail
go test ./adapter/outbound ./protocol/group ./provider/... ./route ./experimental/clashapi
