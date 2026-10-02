# Smart business-context selection

Smart keeps a decision per business context instead of one global node. The
context key is the network fingerprint, the classified service/site, and the
transport (`tcp` or `udp`). For example, `service:search/tcp` and
`service:chat/tcp` may retain different nodes at the same time. Confirmation,
cooldown, site stickiness, failure recovery, and connection interruption all
use this same key, so a decision for one service cannot make another service
switch.

Contexts are scoped to one Smart outbound group. A context only ranks the
leaves configured in that group; it never imports candidates from another
region or Smart group. The group-level `now` field remains a compatibility
view for clients that only understand selector-style APIs. Consumers that
need the actual business decision should read `contexts[]`.

Provider aliases are deduplicated by an opaque `endpoint_id`. Structured
provider options produce a content-addressed `endpoint:<sha256>` ID; legacy
or static candidates use a `policy:<hex>` hash. IDs contain no URL,
credential, or query data. Candidate snapshots, selected context snapshots,
and `recent_switches[]` expose the IDs so monitoring can aggregate aliases
without counting a provider refresh as a real switch.

When destination metadata is available during transparent pre-match, Smart
first consults that context's selection. If it is unavailable, it falls back
to the manual/temporary override and then the last group-wide selection. This
keeps the fast path deterministic while preserving the group boundary.
