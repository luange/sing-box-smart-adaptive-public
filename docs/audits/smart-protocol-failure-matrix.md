# Smart protocol failure matrix

Smart observes one shared stream/packet wrapper, so protocol failures are
classified after the proxy socket has connected instead of being treated as a
normal site response. The classifier is in `protocol/group/smart.go` and is
compiled into both full and slim builds; a slim build does not need to carry a
protocol implementation for the safety rules to remain consistent.

Covered protocol families include VLESS/VMess, Trojan, Shadowsocks and
Shadowsocks 2022, TUIC, Hysteria/Hysteria2, SOCKS4/5, HTTP CONNECT, Snell,
AnyTLS, Naive, SSH, OpenVPN and OpenConnect. WireGuard and Tailscale expose
readiness/handshake failures from `DialContext` or `ListenPacket`, so those
errors already enter the same data-plane failure path without relying on text
markers. Generic TLS certificate errors, HTTP 403/429 responses, EOF and
one-way UDP timeouts remain site-local or soft evidence.

TCP protocol sentinels call the normal Go health store and then publish the
result to the Zig policy backend on the next snapshot; Zig does not maintain a
second breaker. UDP/QUIC protocol sentinels use the same transport-scoped
callback, while ordinary packet loss still requires the response watchdog.
This keeps UDP capability failures from evicting a node's TCP profile.

The table-driven tests in `protocol/group/smart_integration_test.go` cover
positive markers and negative application/TLS cases. Any new protocol should
add its stable parser/authentication sentinel to that test before adding a
marker; broad strings such as `unexpected status` or `certificate` are
intentionally excluded to prevent false node eviction.
