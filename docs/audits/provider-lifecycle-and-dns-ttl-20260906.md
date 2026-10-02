# Provider lifecycle and DNS promotion audit (2026-09-06)

## Fixed in this pass

- Selector and URLTest now publish immutable `(tags, outbound)` snapshots. A
  provider refresh replaces the whole view, so removed members cannot remain
  selectable and readers cannot observe a map/slice half-update.
- Provider-only groups are valid at construction time. Explicit members remain
  supported and duplicate provider names receive deterministic display suffixes.
- Provider callback handles are retained and unregistered on close. Partial
  provider resolution cannot leave a callback subscribed, and repeated starts
  cannot register the same callback twice.
- URLTest starts from one complete snapshot (explicit members are not appended
  twice), invalidates removed TCP/UDP selections, and ignores callbacks during
  the pre-group startup window.
- v3 DNS observations carry the answer RR TTL. Userspace caps promotion by the
  configured maximum and refuses to promote zero-TTL answers.
- v3 promoted DIRECT prefixes are now serialized with publication/close and are
  actively revoked by the UDP cleanup loop when their expiry is reached. Failed
  revocations remain tracked for retry.

## Deliberate boundaries

`use_all_providers` subscribes to the optional ProviderManager observer when
available, so create/replace/remove is reconciled without a polling goroutine.
External managers that do not implement the optional observer retain their
snapshot semantics and are refreshed on the next group reconciliation. Domain
matching remains userspace authoritative; the TC sniffer is advisory and
fail-open.

## Verification

The portable group and v3 ABI tests pass, including the race-enabled group
suite. Linux CI must regenerate the v3 object after the ABI-4 TTL layout change,
run the verifier/load matrix, and publish the resulting embedded object before
any production deployment.
