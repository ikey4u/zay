# zay fork notes

This directory vendors `h3` 0.0.8 (MIT) from `hyperium/h3`. The source is
otherwise kept at the published crate release.

The local delta backports upstream commit
`e07e69412876f7e26f026bd75a48b2704d8c8283` (`hyperium/h3#322`). Standard
HTTP/3 CONNECT requests now omit `:scheme` and `:path` as required by RFC 9114
section 4.4. This is required for NaiveProxy interoperability with the pinned
Go sing-box/quic-go server; quic-go correctly rejects the old field set with
`H3_MESSAGE_ERROR`.

The fork also carries warning-only source hygiene for Rust 1.91 (explicit
elided lifetimes and names for values used only by the optional tracing
feature); these changes do not alter the wire protocol.

Keep this delta when updating the vendored release, or remove the fork once a
published `h3` release containing that upstream commit is adopted.
