# v3 DNS observation completion audit (2026-09-06)

## Scope

This closes the previously unfinished domain-direct path. TC v3 now observes
only plaintext UDP responses whose source port is 53; it never changes the
packet verdict. A bounded `v3_dns_observe` LRU map carries a normalized qname
and the first matching A/AAAA answer to the userspace control plane.

## Safety and lifecycle

- The parser accepts one question, successful responses, uncompressed names,
  and RFC 1035 compression pointers with bounded hops/steps. Invalid,
  fragmented, truncated, non-IN, non-A/AAAA, and overlong records are
  discarded fail-open.
- The DNS walk is limited to the UDP datagram length and fixed-size stack/map
  copies are zero-initialized, keeping verifier and stack bounds explicit.
- The map is capped at 4096 rows. Userspace drains at most 128 rows every
  three seconds and reuses the existing route-rule safety check, hint conflict
  isolation, TTL, and revocable DIRECT promotion path.
- Drain admission is v3/DNS-hint-only; v2 fallback and FakeIP-only mode do not
  start the monitor or accidentally enable real-DNS promotion. Close cancels
  and joins the monitor before the shared backend is torn down.
- `dns_ip_hint=off` disables the sniffer. Source-sensitive MAC policy still
  blocks global DNS/IP promotion until a source-aware observer exists.

## ABI and build gates

The v3 ABI is version 4. Native runtime and the optional XDP loader both bind
the new map FD. Linux CI regenerates the v3 object, checks BTF/maps/source
sections and the `v3_dns_observe` symbol, and runs the tagged Go/race/vet
matrix. eBPF objects are not generated on macOS.

The observation value now carries the authoritative RR TTL. Userspace clamps
that value by the configured promotion TTL before publishing a DIRECT /32 or
/128. A bounded GC runs with the UDP cleanup loop and revokes expired entries
from the active v3 bank; failed revocations remain tracked for retry.

## Verification performed

Portable tests cover ABI sizes, flag semantics, FakeIP/DNS-hint separation,
hostname validation, and existing Smart/eBPF lifecycle paths. Full `go test
./...` and focused `go vet` pass locally; Linux object generation and kernel
verifier/load remain CI-gated.
