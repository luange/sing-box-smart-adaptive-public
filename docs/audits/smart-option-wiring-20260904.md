# Smart option consumer audit

This audit is a source-level check that every public Smart option either
changes runtime behavior or is deliberately owned by the host. It prevents
configuration fields from becoming decorative API.

| Option family | Consumer | Owner |
| --- | --- | --- |
| `url`, probe interval/timeout/cycle/concurrency | shared TCP/UDP/family probe scheduler | Go host |
| `max_attempts`, `attempt_timeout`, `established_stall_timeout` | bounded dial/hedge and passive stall watchdog | Go host |
| `site_stickiness`, switch confirmation/cooldown/margin/min improvement | primary/backup FSM and Zig policy ABI | Go + Zig |
| `selection_mode`, `exploration`, `min_samples` | stable affinity and confidence/exploration scoring | Zig ABI in packaged builds; Go host policy remains a development fallback |
| throughput floor/samples | passive bulk signal, status and bulk score | Go host |
| breaker, half-life, retention, max entries | portrait decay, circuit state and bounded in-memory pruning | Go host |
| provider/catalog filters and node weights | candidate discovery and score normalization | Go host |
| interrupt policy | selective connection interruption after a confirmed failover | Go host |

`history_path` was removed because Smart health is process-local and no runtime
reader or writer consumed it. The unused URLTest `fallback` schema was removed
for the same reason. `min_samples` is now carried through Smart ABI version 5;
the Zig affinity gate no longer silently assumes three samples when an operator
chooses another confidence floor. `selection_mode` remains a compatibility
alias, but all accepted values intentionally use the one unified policy.

Options that prepare evidence or own I/O stay out of Zig by design. Adding them
to the policy kernel would duplicate schedulers, sockets, or health stores and
would make the two implementations less deterministic.

The build contract is fail-closed for production: release jobs must include
`smart_zig,production_smart`; a production build without Zig reports
`policy_backend=unavailable` and refuses to construct Smart. Ordinary untagged
builds retain the host policy for development and conformance.
