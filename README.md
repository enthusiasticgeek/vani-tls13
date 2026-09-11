# tls13

TLS 1.3 (`TLS_CHACHA20_POLY1305_SHA256`, X25519 key exchange, Ed25519
signatures, RFC 7250 raw public keys — no X.509/CA chain) handshake +
record layer, pure vāṇी, hardware-agnostic and heap-free.

Extracted from [Dhruva OS](https://github.com/enthusiasticgeek/dhruvaos)'s
Pi 4/5 port (round 166), itself a faithful port of DhruvaOS's Pi 1
kernel's own original TLS 1.3 implementation — so both boards, and any
future one, share this one implementation instead of each keeping its
own copy.

## Scope

This package is the pure protocol/crypto-orchestration layer only:
wire-format helpers, handshake message builders (ClientHello/
ServerHello/EncryptedExtensions/Certificate/CertificateVerify/
Finished), HMAC-SHA256 + HKDF-Extract/Expand/Expand-Label, transcript
hashing, the key schedule (handshake and application traffic secrets),
and the AEAD record layer (encrypt/decrypt). No scratch-buffer/heap
dependency at all — everything threaded through function parameters
and return values as fixed-size local arrays.

**Not included** (deliberately, matching every other DhruvaOS-
extracted package's mechanism/policy split): a stateful live-transport
service loop, session persistence across separate poll/call cycles,
TCP-transport chunking of records into a byte stream, and any real
network I/O. A consumer wires this package's pure functions into its
own board-specific transport and session-state handling.

## Dependencies

Vendored at `./vendor/<name>` and pulled in via direct relative `use`
statements, not `vani.toml` `[deps]` entries — see `vani-pki`'s own
README for why (a real vani-compiler bug, BUG-234 in
`vani-compiler/docs/TODO_CURRENT.md`, breaks internal name resolution
for `[deps]`-vendored packages whose code assigns a function call's
result into an array element).

- [`crypto_hash`](https://github.com/enthusiasticgeek/vani-crypto-hash) — SHA-256 for HMAC/HKDF/transcript hashing.
- [`curve25519`](https://github.com/enthusiasticgeek/vani-curve25519) — X25519 key exchange, Ed25519 sign/verify for `CertificateVerify`.
- [`chacha20_poly1305`](https://github.com/enthusiasticgeek/vani-chacha20-poly1305) — the AEAD record layer.

## API

```
// Wire-format helpers
fn tls_write_u8/u16/u24/bytes32/bytes64(buf: mut ref [u8; 512], pos: i64, ...) -> i64
fn tls_basepoint32() -> [u8; 32]
fn tls_bytes_equal32(a: ref [u8; 32], b: ref [u8; 32]) -> i64
fn tls_bytes_equal512(a: ref [u8; 512], b: ref [u8; 512], n: i64) -> i64

// Handshake message builders (return the message's byte length)
fn tls_build_client_hello(client_random: ref [u8; 32], client_pub: ref [u8; 32], out: mut ref [u8; 512]) -> i64
fn tls_build_server_hello(server_random: ref [u8; 32], server_pub: ref [u8; 32], out: mut ref [u8; 512]) -> i64
fn tls_build_encrypted_extensions(out: mut ref [u8; 512]) -> i64
fn tls_build_certificate(raw_pubkey: ref [u8; 32], out: mut ref [u8; 512]) -> i64
fn tls_build_certificate_verify(sig: ref [u8; 64], out: mut ref [u8; 512]) -> i64
fn tls_build_finished(verify_data: ref [u8; 32], out: mut ref [u8; 512]) -> i64
fn tls_certverify_signed_content(transcript_hash: ref [u8; 32], out: mut ref [u8; 512]) -> i64

// HMAC / HKDF / transcript hashing / key schedule
fn tls_hmac_sha256(key: ref [u8; 32], msg: ref [u8; 256], msg_len: i64) -> [u8; 32]
fn tls_hkdf_extract(salt: ref [u8; 32], ikm: ref [u8; 32]) -> [u8; 32]
fn tls_hkdf_expand(prk: ref [u8; 32], hklabel: ref [u8; 512], hklabel_len: i64, out_len: i64) -> [u8; 32]
fn tls_hkdf_expand_label(secret: ref [u8; 32], label: Str, context: ref [u8; 32], context_len: i64, length: i64) -> [u8; 32]
fn tls_hash_transcript(transcript: ref [u8; 1024], transcript_len: i64) -> [u8; 32]
fn tls_derive_secret(secret: ref [u8; 32], label: Str, transcript: ref [u8; 1024], transcript_len: i64) -> [u8; 32]
fn tls_derive_traffic_keys(secret: ref [u8; 32]) -> TlsTrafficKeys   // { key: [u8;32], iv: [u8;12] }
fn tls_finished_verify_data(traffic_secret: ref [u8; 32], transcript: ref [u8; 1024], transcript_len: i64) -> [u8; 32]

// Record layer (content_type: 22=handshake, 23=application_data)
fn tls_record_nonce(static_iv: ref [u8; 12], seq: i64) -> [u8; 12]
fn tls_encrypt_record(key: ref [u8; 32], static_iv: ref [u8; 12], seq: i64, content: ref [u8; 512], content_len: i64, content_type: i64) -> TlsEncryptResult   // { rec: [u8;512], span_len: i64 }
fn tls_decrypt_record(key: ref [u8; 32], static_iv: ref [u8; 12], seq: i64, rec_data: ref [u8; 512], record_len: i64, expected_content_type: i64) -> TlsDecryptResult   // { ok: i64, content: [u8;512], span_len: i64 }

fn tls13_self_test() -> i64   // 1 = pass, 0 = fail; no I/O side effects
```

## Verification

`tls13_self_test()` runs a full client+server handshake (ClientHello
through both Finished messages) and an application-data round trip in
both directions using deterministic test vectors, checking every
message's own encrypt→decrypt round trip plus a deliberate tampered-
record rejection check. Passes under `vanic run test/host_test.vani`
(host LLVM JIT) and has been verified live on real (QEMU-emulated)
AArch64 hardware as part of DhruvaOS's Pi 4/5 boot sequence.

`vanic run test/host_test.vani --backend=c` currently fails — a
pre-existing, unrelated vani-compiler C-backend bug in the vendored
`crypto_hash` package's own struct-literal codegen for array-typed
struct fields (confirmed via `crypto_hash`'s own standalone test), not
something introduced by this package. See
`vani-compiler/docs/DHRUVAOS_ERGONOMICS_TODO.md` gap #5.
