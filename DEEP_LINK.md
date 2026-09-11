# TrustTunnel deep links (`tt://`)

FreeTunnel imports VPN configurations from **TrustTunnel deep links** — the same
format used by QR codes and mobile clients.

## URI format

```text
tt://?<base64url-payload>
```

- Scheme is case-sensitive: `tt`
- Payload is the query body (after `?`), encoded as **base64url** (RFC 4648,
  no padding).
- Share links that embed the same payload are also accepted, e.g.
  `https://trusttunnel.org/qr.html#tt=<base64url>` or `?tt=<base64url>`.

Implementation: `src/core/DeepLink.cpp`, `include/core/DeepLink.h`.

## Binary payload: TLV encoding

The decoded payload is a sequence of **type-length-value** records. Both tag and
length use **QUIC variable-length integers** (RFC 9000 §16), not fixed-width
fields.

Each record:

| Field | Encoding |
| --- | --- |
| Tag | QUIC varint |
| Length | QUIC varint (byte length of value) |
| Value | Raw bytes |

Unknown tags are ignored (forward compatibility). Maximum supported format
version: **1** (`kDeepLinkMaxVersion`).

## Field tags

| Tag | Field | Type | Required | Default |
| --- | --- | --- | --- | --- |
| `0x00` | Version | varint | no | `0` |
| `0x01` | Hostname | UTF-8 string | **yes** | — |
| `0x02` | Address | UTF-8 string `host:port` | **yes** (≥1) | — |
| `0x03` | Custom SNI | UTF-8 string | no | empty |
| `0x04` | Allow IPv6 | 1 byte bool | no | `true` |
| `0x05` | Username | UTF-8 string | **yes** | — |
| `0x06` | Password | UTF-8 string | **yes** | — |
| `0x07` | Skip verification | 1 byte bool | no | `false` |
| `0x08` | Certificate | concatenated DER | no | empty |
| `0x09` | Upstream protocol | varint | no | `1` (HTTP/2) |
| `0x0A` | Anti-DPI | 1 byte bool | no | `false` |
| `0x0B` | Client random prefix | UTF-8 `prefix[/mask]` hex | no | empty |
| `0x0C` | Display name | UTF-8 string | no | empty |
| `0x0D` | DNS upstreams | string list | no | empty |

### Tag `0x09` — upstream protocol

| Value | Protocol |
| --- | --- |
| `1` | HTTP/2 |
| `2` | HTTP/3 |

### Tag `0x0D` — DNS upstream list

Value is a concatenation of entries: each entry is `varint length` + UTF-8 bytes.

### Tag `0x0B` — client random

UTF-8 string `prefix` or `prefix/mask` (hex). Slash separates prefix and mask.

## Validation rules

Import fails when:

- URI is not `tt://…`
- Base64url payload is invalid or empty
- TLV stream is truncated or length overflows payload
- `version > 1`
- Missing hostname, any address, username, or password
- Malformed DNS upstream list

Passwords from deep links are stored in the OS credential store, not in the
on-disk TOML.

## TOML generation

`deepLinkConfigToToml()` maps the parsed config to TrustTunnel client TOML
(matching the in-app create-config form). Control characters in string fields
are stripped to prevent TOML injection from crafted links.

## FreeTunnel control links (separate)

Application control uses a different scheme (not TLV):

| URI | Action |
| --- | --- |
| `freetunnel://toggle` | Toggle VPN |
| `freetunnel://connect` | Connect |
| `freetunnel://disconnect` | Disconnect |

Handled by `ControlCommand.cpp` and forwarded to a running single-instance app
via a local socket.

## Tests

Round-trip encode/decode, injection stripping, and edge cases are covered in
`tests/test_deeplink.cpp` and `tests/test_configimport.cpp`.
