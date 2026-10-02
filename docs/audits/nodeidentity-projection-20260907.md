# Node identity projection audit (2026-09-07)

## Scope

Path identity is shared by Smart/AdaptivePool reachability probes, while dial
identity remains credential-sensitive. The previous implementation used one
recursive blacklist for both every protocol and every nested object.

## Changes

- Added `CanonicalEndpointOptionsForType`, with explicit credential projections
  for VLESS, VMess, Trojan, Shadowsocks( R ), Hysteria(2), TUIC, WireGuard,
  SSH, SOCKS/HTTP/Naive, Snell, OpenVPN, OpenConnect and Tailscale.
- Transport, TLS, SNI, routing and protocol-mode fields remain in the path
  identity. `Authorization` is removed only inside header maps; custom header
  fields such as `Token` are preserved.
- Unknown protocol types retain the old conservative projection, so a new
  protocol cannot silently lose fields before its projection is reviewed.
- Provider and Smart identity builders now use the protocol-aware projection.
- Removed the unused `appendProviderMembers` helper and its obsolete direct
  test; all production groups use immutable snapshot rebuilds.

## Verification

`go test ./common/nodeidentity ./adapter/provider ./protocol/group/...` and the
same packages with `-race` pass. Tests cover SSH credential variants,
HTTP header preservation and OpenVPN authentication algorithm retention.
