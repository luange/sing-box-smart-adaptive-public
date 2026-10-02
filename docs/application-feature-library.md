# Application Feature Library

Smart can augment sing-box's native TLS SNI and HTTP Host sniffing with a
private Panabit PDB package:

```json
{
  "type": "smart",
  "tag": "HK",
  "application_feature_library": "/etc/sing-box/private/dpi.pdb",
  "outbounds": ["node-a", "node-b"]
}
```

The loader reads the original gzip/tar package directly. It scans the fixed
application records in `dict.so`, then resolves `snikey_data` and
`hostkey_data` through `dpi.so`'s ELF symbols and relocations. Shared objects
are never loaded or executed. The commercial feature data is not embedded in
the sing-box binary or repository.

## Evidence semantics

1. Built-in semantic families (for example YouTube/OpenAI/Telegram) remain
   authoritative because they deliberately group several related services.
2. TLS/QUIC uses the PDB SNI table; plain HTTP prefers the Host table. The
   tables remain separate when the same suffix maps to different apps.
3. Matching uses the longest valid suffix. `^` entries are exact-only.
4. Invalid domain syntax, handler-backed records, and ambiguous duplicate
   mappings are rejected and counted in the startup log.
5. Application identities are emitted as `app:<name>` and become stable Smart
   business-family keys. Generic transport names such as `tls` and `quic`
   never become applications.

This integration reproduces data-driven SNI/Host classification. Panabit's
compiled TCP/UDP behavior handlers are not executed; equivalent native
sing-box sniffers must be implemented and tested protocol by protocol.
