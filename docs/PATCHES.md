# oSIP local patches

Base: official GNU oSIP **5.3.2** release. The archive, SHA256, Git ancestor,
and imported release files are recorded in `ORIGIN.md`.

## Authentication parameters

Authorization and WWW-Authenticate share a native scanner for token names,
quoted strings, escaped characters, and token values. Proxy-Authorization and
Proxy-Authenticate reuse these types. Existing typed fields preserve their raw
wire values; unknown fields are owned `osip_generic_param_t` elements in
`auth_params`. `osip_authorization_get_param` and
`osip_www_authenticate_get_param` look up both known and unknown fields without
case sensitivity. Quoting, escapes, embedded commas and semicolons survive
parse, clone, serialize, and free paths. Extension fields are emitted once.

Duplicate names are rejected without case sensitivity, including known fields.
Malformed escapes, controls, empty unquoted values, and unterminated quoted
strings are rejected. Legacy space separators and adjacent quoted fields are
accepted for deployed GB35114 peers. Basic/NTLM/Negotiate token68 credentials are
retained in the existing `auth_param` slot. Invalid authentication headers fail
message parsing instead of silently disappearing.

`OSIP_AUTH_PARAMS_API=1` identifies this ABI extension. Consumers must rebuild
against these headers when enabling the extension.
Business meaning, backend calls, signatures, and national-standard field names
remain outside oSIP. The parser does not contain GB-specific field names.

## Message framing and serialization

Complete-message parsing checks Content-Length for decimal syntax, size_t
overflow, truncation, and trailing bytes. An absent length retains upstream UDP
inference behavior; SIP-fragment parsing is unchanged. Serialization reserves
enough decimal digits for size_t body lengths instead of five characters,
avoiding an underflow when a Catalog body exceeds 99,999 bytes.

## Windows headers

The two internal platform headers include winsock2 before Windows headers,
providing timeval even with WIN32_LEAN_AND_MEAN and OSIP_MONOTHREAD.

## CMake and platform integration

The standalone CMake build exposes separate parser and transaction libraries,
with static/shared, monothread, minisize, trace, and installation options.
`OSIP_MONOTHREAD`, `MINISIZE`, and trace settings propagate to consumers through
exported targets. Build instructions are in `BUILDING.md`.

Windows minisize maps case-insensitive string comparisons to the same CRT
functions used by the full build. The upstream test driver reads wire messages
in binary mode and reports matching expectations consistently across platforms.
Its explicit error override lets the existing strict framing/authentication
patches retain their rejection contract against upstream's permissive fixtures.

All changes retain the upstream LGPL-2.1-or-later license. CMake validation uses
Debug builds on Windows/MSVC and Linux/GCC, including installed-package consumers.
The Autotools build has not been revalidated in this change.
