# Dynamic DIRECT map refactor

Learned DIRECT prefixes are runtime evidence, not static policy. They are
stored in separate v3 LPM maps with an expiry deadline and current policy
generation.

- Static policy is published atomically through the double bank. A static
  proxy/block verdict always wins over a learned DIRECT prefix.
- `MergeDynamicDirect(prefix, ttl)` refreshes an existing row without using a
  new slot, reclaims expired rows before capacity checks, and fails open when
  all bounded slots are live.
- A policy generation change clears tracked dynamic rows after the static
  flip succeeds. A failed static transaction leaves valid runtime learning
  intact.
- `DeleteMergedStaticDirect` is a compatibility façade that can remove only a
  learned row; it cannot delete a snapshot-published rule.
- The pure memory backend and `decision.go` model the same precedence as the
  kernel (`static -> exact flow -> dynamic -> DNS hint -> socket assign`).

The kernel map is intentionally not an LRU: user space owns expiry tracking so
stale rows are explicitly deleted before a fixed-capacity map can fill.
