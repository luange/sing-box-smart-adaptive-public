# Smart protocol semantic audit (2026-09-05)

This audit covers every upstream protocol family that can be exposed as a
Smart leaf. It separates failures that prove the proxy/VPN endpoint is bad
from failures that only describe the destination service.

| Family | Failure stage | Smart path | Scope |
| --- | --- | --- | --- |
| VLESS, VMess, Trojan | framing, auth, response header | stream wrapper marker -> data-plane failure | endpoint/site/transport |
| Shadowsocks, Shadowsocks 2022, Snell | AEAD/salt/session/header | stream or packet wrapper marker -> data-plane failure | endpoint/site/transport |
| SOCKS4/5, HTTP CONNECT | method/auth/tunnel negotiation | stream marker or dial error -> failure observer | endpoint/site/transport |
| AnyTLS, Naive, ShadowTLS | session/auth/HTTP2 or QUIC framing | stream/packet marker or dial error -> failure observer | endpoint/site/transport |
| Hysteria, Hysteria2, TUIC | QUIC auth/control/UDP capability | packet marker; response watchdog only for transactional UDP | UDP transport, then endpoint after repeated evidence |
| SSH | handshake, host-key, cipher, authentication | dial/stream error -> failure observer | endpoint/site/transport |
| OpenVPN, OpenConnect | control/data packet, auth, CSTP | dial/stream marker -> failure observer | endpoint/site/transport |
| WireGuard, Tailscale | readiness/peer negotiation | `DialContext`/`ListenPacket` error -> failure observer | endpoint/transport |
| Tor | process/bootstrap/SOCKS dial | dial error -> failure observer | endpoint/site |
| Direct, bridge, TUN, DNS and block/pass | no proxy handshake | ordinary dial result only | destination/path |

The shared stream and packet wrappers are the only post-connect observation
boundary. `unknown version: 72`, authentication/framing sentinels and VPN
control errors cannot bypass it, including when a reader returns data and an
error in the same call. Caller cancellation, normal EOF, certificate errors
and HTTP 403/429 remain non-node evidence. One-way UDP is not penalized; only a
transactional flow that reached its response threshold can trip the watchdog.

The complete positive/negative marker matrix is in
`protocol/group/smart_integration_test.go`. Dial-time failures are covered by
the same-request failover tests. The release matrix compiles all protocol
packages with `release/DEFAULT_BUILD_TAGS_OTHERS`; the gateway artifact uses a
smaller, explicit tag set and is checked separately. Adding a protocol requires
one stable parser/authentication sentinel test or an explicit dial-only entry
in this table before it can affect node health.
