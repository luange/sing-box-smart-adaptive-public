# Smart memory and ranking optimization

Date: 2026-08-31

## Scope

This change targets the control-plane costs visible during high connection
fan-out (browser pages, QUIC asset bursts and API polling). It does not change
candidate health thresholds, switch confirmation, failure recovery or the
data-plane forwarding path.

## Changes

- Provider refresh now builds one immutable `tag -> metadata` snapshot per
  candidate: canonical endpoint identity, profile id, probe key, policy id and
  weight match. Ranking reuses this map instead of retaining a second identity
  map plus a parallel metadata slice.
- Ranking scratch buffers contain only candidates and final ranks; they remain
  bounded by the existing pool limit. Test-only Smart instances still use a
  safe fallback snapshot.
- `smartStore.estimate` copies metrics by value and returns presence flags;
  temporary metric pointers no longer escape from the ranking hot path.
- Identical Smart status decisions are coalesced for 200ms. Selection changes,
  phase changes, failures and context changes still publish immediately.
- Traffic-family resolution bypasses the lineage lock for ordinary domains;
  only parent/inherited families use the shared lineage state.

## Safety and compatibility

Provider rebuilds replace candidates and metadata together under one read-side
snapshot boundary; the old metadata map is never mutated after publication.
The status throttle only delays repeated dashboard snapshots;
it never delays dialing, probing or failover.

## Verification

Passed:

- `go test -race ./protocol/group/... ./common/nodeweight/... ./protocol/group/trafficfamily/...`
- `git diff --check`
- compiler escape inspection for `smartStore.estimate`

The repository-wide macOS test run still has pre-existing RC merge failures in
provider parser/libbox build-tag coverage and route/rule assertions; those are
outside this change and must be resolved in the Linux CI baseline before a
release build is considered publishable.
