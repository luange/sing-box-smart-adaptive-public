# Smart state-key contract

Smart state is deliberately split into identity layers. A display name or
provider object address is never used as a health key.

| Key | Scope | Required invariant |
|---|---|---|
| `PathIdentity` | Reachability probes and probe single-flight | Aliases and credential variants for the same network path share probe work. |
| `DialIdentity` | Authentication/data health, breaker, quarantine, use score, retry diversity | Credentials or transport parameters that can fail independently remain distinct. |
| `probeKey` | Probe URL, address family, transport and timeout | The same path may have separate TCP, DNS, UDP, IPv4 and IPv6 evidence. |
| `policyID` | Zig ordering and policy snapshots | Stable hash of `DialIdentity`; it contains no secret material. |
| `DisplayTag` | Dashboard/API only | Renaming or numeric suffixes never creates a new health profile. |
| site/transport key | Selection context | Context changes affinity only; it does not rewrite endpoint identity. |
| provider tag/source | Membership lifecycle | Reloads can add/remove aliases without orphaning or cross-attaching state. |

## Selection and dial invariants

1. One dial plan uses an endpoint at most once per `DialIdentity`; aliases do
   not create fake hedge/retry diversity.
2. Zig is the only selection-state owner. Go owns evidence and breaker state;
   it exports `open/eligible` snapshots and invalidation events.
3. Every selection has a generation. New connections must report the selected
   `DialIdentity` and generation to the observation path; a mismatch is an
   error metric, not a silent fallback.
4. Provider reload remaps by identity, removes deleted identities, and never
   copies a profile to a newly introduced endpoint merely because its tag was
   reused.

These rules are part of the Smart integration tests and should be preserved
when adding a new provider or backend.
