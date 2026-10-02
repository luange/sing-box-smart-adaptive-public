# Smart gate parity audit

This audit compares the requested Surge-style gates with the current Smart
implementation. Names from other clients are not copied into the ABI; the
host adapter owns network capabilities and the Zig policy kernel owns ranking.

| Requested behavior | Current implementation | Result |
| --- | --- | --- |
| Exclude an undetectable-error candidate | No field named `hasUndetectableErrorForSmartGroup`; candidates are filtered by transport support, circuit state, and the shared probe registry. | Equivalent gates exist, but this exact flag is not implemented. |
| Exclude UDP-incompatible candidates | `rankPooled` and the UDP probe scheduler require `N.NetworkUDP`. | Implemented. |
| Empty candidate fallback to DIRECT/REJECT | Smart returns a typed no-candidate error; the surrounding route decides DIRECT or REJECT. | Host-owned, not a Smart selector decision. |
| 50 ms A/B/C score bands | Health tiers (`healthy`, `warming`, `suspect`, `open`) sort before confidence-adjusted p95 score. | Not implemented as a 50 ms band, intentionally. |
| Site failure stain with one-success/TTL clearing | Site-local store metrics open after repeated failures and decay by half-life; success clears consecutive failures. | Implemented with stronger repeated-failure semantics; no literal one-hour field. |
| Site stickiness and sample sufficiency | Affinity TTL, incumbent retention, switch margin/confirmation/cooldown, and canonical service identity. | Implemented; no literal 70% shortcut. |
| Untested exploration priority | Unknown/warming candidates receive bounded exploration while healthy incumbents remain sticky. | Implemented with hysteresis rather than unconditional priority. |
| `bestHandshakeTime` failover deadline | No such field exists. Dial failover is bounded by `attempt_timeout`; established stalls use `established_stall_timeout`. | Not implemented; no consumer to preserve. |

## Corrective change

Background probes remain fail-open when every candidate fails the same probe
endpoint, so a Cloudflare/204 outage cannot evict the whole catalog. Real
data-plane failures are stronger evidence: the affected site and transport are
quarantined for 30 seconds immediately, while the endpoint-global portrait is
left usable for other services. The next request therefore skips a dead
incumbent without waiting for three failures, and the normal breaker still
handles repeated failures and exponential recovery.

The behavior is covered by
`TestSmartDataPlaneFailureSkipsDeadIncumbentOnNextRequest` and
`TestSmartDataPlaneFailureQuarantinesOnlyAffectedSite`.

UDP coverage uses the same bounded scheduler in the production path: each
cycle rotates never-probed/oldest EndpointProfiles, caps the batch at two, and
checks IPv4/IPv6 serially. `TestSmartUDPProbeBudgetIsUsedByProductionPath`
guards the wiring so the scheduler cannot silently degrade to first-N order.
