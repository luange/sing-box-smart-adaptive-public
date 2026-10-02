# RC5 baseline and production gate record

Date: 2026-08-30

## Baseline

The branch `adaptive/official-rc5-smart-ebpf-audit` incorporates the official
`v1.14.0-rc.5` source at commit `c881f561e9304ac7a2662d27d80394b3fec1b96c`.
The RC5 delta was applied on top of the project-maintained RC4 tree rather than
discarding Smart/eBPF changes.  The upstream dependency updates include the
QUIC, sing-tun, and Tailscale patch revisions; RC5's selector, URL-test,
WebSocket, daemon, and Clash API changes were retained alongside the shared
EndpointProfile/Smart behavior.

## Gates

- RC5 Smart/eBPF global audit: GitHub Actions run `33320488475` — passed on
  commit `ba372d46`.
- XDP engine: GitHub Actions run `33320488469` — passed on commit `ba372d46`
  (Zig tests, x86_64/aarch64 libraries, C ABI, object policy scan).
- Linux release matrix: GitHub Actions run `33320567889` — passed on commit
  `ba372d46` for amd64/arm64 × glibc/musl; release publication was disabled
  for this gate. Artifacts were retained by Actions.
- The follow-up AF_XDP ring hardening is in commit `d18d13c3`: checked ring
  offsets, overflow-safe pointer construction, and partial shared-ring cleanup.
- XDP backpressure hardening is in commit `ba372d46`: the host-neutral queue
  model reserves peer TX capacity before consuming RX, so a full peer ring
  keeps the frame available for TC/kernel fallback instead of losing it.
- Embedded v2 eBPF provenance is checked before regeneration in commit
  `fd6d45cc`.

## Production boundary

TC v3 remains the production data plane.  AF_XDP is still opt-in and fail-open:
DIRECT-only traffic may use it only after mode-specific attach, complete XSK
publication, and a multi-queue host probe.  The Go migration gate continues to
reject `shared_network.xdp.enabled=true` until the host adapter is wired to a
privileged, bidirectional lab.  No AF_XDP attach is permitted on VM107 or
VM115, and no production deployment is implied by the CI artifacts.
