# rustls protocol compatibility patch

This directory vendors rustls 0.23.40. It remains under rustls' original
Apache-2.0/ISC/MIT licensing.

The local delta combines the audited shaped-rustls branch at commit
`3a131beaef0183b0cb61e5a9070a703b6be39ed3`, the rustls server-ECH pull request
2993 at commit `3e80839`, and one existing zay hook. Both upstream deltas remain
under rustls' Apache-2.0/ISC/MIT licensing. The ECH work was adapted from the
0.24 development state-machine API to this 0.23.40 fork; it retains ECHConfig
key resolution, HPKE decryption, ClientHelloInner reconstruction, confirmation
signals, HelloRetryRequest handling, retry configs, and certificate-resolution
rewind semantics. The shaping branch exposes generic, protocol-independent
ClientHello planning, capture and length-preserving finalization APIs. singbox
uses those APIs for ShadowTLS, uTLS and REALITY without maintaining mutually
incompatible TLS forks.

The zay-specific delta intentionally exposes one additional compatibility
hook:

- `ConnectionCommon::dangerous_take_read_ahead`, which atomically drains
  already-decrypted plaintext and unconsumed raw TLS input. VLESS Vision uses
  those two buffers, in that order, when its authenticated Direct command
  transfers ownership of the underlying byte stream away from the outer TLS
  record layer.

The singbox ShadowTLS adapter installs a `FinalizesClientHello` implementation
and disables TLS resumption. That keeps PSK binders out of the ClientHello:
binders otherwise create a circular dependency between themselves and the
ShadowTLS session-ID HMAC. The same generic finalizer is capable of sealing a
REALITY session ID before capture, transcript submission and network write.

Principal shaped-rustls production files changed from upstream:

- `src/client/client_hello.rs`: public, bounded ClientHello plan types.
- `src/client/client_conn.rs` and `src/client/builder.rs`: customizer field.
- `src/client/hs.rs`, `src/client/tls12.rs`, `src/client/tls13.rs` and
  `src/msgs/handshake.rs`: apply and validate shaping/finalization plans.
- `src/crypto/aws_lc_rs/*`: fixed X25519/PQ key-share support used by the
  shaping plan.
- `src/msgs/deframer/buffers.rs`: consume the complete available application-
  data window, matching the audited branch.
- `src/conn.rs`: expose the bounded VLESS Vision read-ahead drain.
- `src/lib.rs`: export the generic ClientHello API.

Principal server-ECH production files changed from rustls 0.23.40:

- `src/server/ech.rs`: ECH keys, resolver API, HPKE frontend/backend state,
  inner ClientHello recovery, HRR continuation and retry configuration.
- `src/msgs/client_hello.rs`: bounded raw ClientHello and extension parsing used
  to reconstruct ClientHelloInner without lossy re-encoding.
- `src/server/hs.rs` and `src/server/tls13.rs`: ECH selection, transcript
  integration, confirmation signals, retry config emission and outer-hello
  rewind when the certificate resolver cannot serve the private name.
- `src/server/server_conn.rs` and `src/quic.rs`: expose accepted ECH frontend
  metadata to stream and QUIC callers.
- `src/tls13/key_schedule.rs`, `src/msgs/message/mod.rs`,
  `src/msgs/handshake.rs`, `src/error.rs`, `src/server/builder.rs` and
  `src/lib.rs`: key-schedule, encoded-message patching, strict parsing,
  configuration defaults, error taxonomy and public API support.
