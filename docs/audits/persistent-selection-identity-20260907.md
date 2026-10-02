# Persistent selection identity audit (2026-09-07)

## Finding

Selector and Smart previously persisted only a display tag. Provider refreshes
can renumber duplicate aliases (`HK #2` becoming `HK`), so a restart could
restore a different endpoint even though live refresh already preserved the
selection by identity.

## Remediation

- Added an optional `adapter.SelectedRecordStore` extension so external
  `CacheFile` implementations remain source-compatible.
- The built-in cache stores a versioned record containing display tag,
  credential-aware `DialIdentity`, and credential-free `EndpointIdentity`.
- The legacy `selected` bucket remains a display-tag shadow for older clients;
  legacy writes invalidate the identity record to prevent stale resurrection.
- Selector and Smart restore in the order DialIdentity, EndpointIdentity, then
  display tag. Legacy tag-only records are migrated after a successful match.
- Smart pins now retain both identities and are remapped when provider members
  are refreshed; Selector persists the remapped record as well.

## Verification

Cache round-trip, legacy migration/invalidation, identity resolution, targeted
group tests, and race tests pass. No credential, URL, or subscription payload
is written to the cache; only opaque identities are persisted.
