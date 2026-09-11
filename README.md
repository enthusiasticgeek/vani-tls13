# tls13

TLS 1.3 (`TLS_CHACHA20_POLY1305_SHA256`, X25519 key exchange, Ed25519
signatures, RFC 7250 raw public keys — no X.509/CA chain) handshake +
record layer, pure vāṇी, hardware-agnostic and heap-free.

Extracted from [Dhruva OS](https://github.com/enthusiasticgeek/dhruvaos)'s
Pi 4/5 port (round 166), itself a faithful port of DhruvaOS's Pi 1
kernel's own original TLS 1.3 implementation — so both boards, and any
future one, share this one implementation instead of each keeping its
own copy. Round 174 completed that circle: added a second,
heap-pointer API (below) and migrated Pi 1's own kernel onto it too,
so both boards now genuinely share one implementation.

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

## core.vani vs. lib.vani

Like `crypto_hash`/`curve25519`/`chacha20_poly1305`, this package ships
both: `src/lib.vani` is the full API plus `tls13_self_test()`, vendoring
its dependencies' own `lib.vani` (which includes THEIR self-tests
too). `src/core.vani` is the same API minus `tls13_self_test()`,
vendoring `core.vani` copies of its dependencies instead — for a
consumer whose own code already defines names colliding with
`sha256_self_test`/`x25519_self_test`/`ed25519_self_test`/
`chacha20_poly1305_self_test`/etc. (DhruvaOS's Pi 1 kernel is the
motivating example). Pick whichever doesn't collide with your own code.

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

### Heap-pointer API (round 174)

A second surface for a consumer whose real record sizes exceed 512
bytes (Pi 1's own TLS records run up to 2048 bytes) -- now that both
DhruvaOS boards have a real heap allocator, both can use this one
package. Every `_heap` function takes `mut ref i64` for whichever
parameter must scale with real content, paired with the project's own
`buf_read_byte`/`buf_write_byte` byte accessors (declared `extern "C"`
here -- a consumer vendoring this package already provides them, e.g.
`boot/dharafs_buf.S` on Pi 1, `boot/rpi4/runtime_stubs_rpi4.c` on Pi
4/5). Most are thin bridging shims over the array API above (every
handshake message is small and bounded regardless of a board's own
record ceiling); `tls_hash_transcript_heap` and `tls_encrypt_record_
heap`/`tls_decrypt_record_heap` are genuinely new, unbounded-length
logic built directly on the vendored packages' own streaming
primitives:

```
fn tls_copy_heap(dst: mut ref i64, dst_off: i64, src: mut ref i64, src_off: i64, n: i64) -> i64
fn tls_put_u8_heap/u16_heap/u24_heap(buf: mut ref i64, off: i64, v) -> i64
fn tls_x25519_basepoint_heap(out: mut ref i64) -> i64
fn tls_bytes_equal_heap(a: mut ref i64, b: mut ref i64, n: i64) -> i64

fn tls_build_client_hello_heap(client_random: mut ref i64, client_pub: mut ref i64, out: mut ref i64) -> i64
fn tls_build_server_hello_heap(server_random: mut ref i64, server_pub: mut ref i64, out: mut ref i64) -> i64
fn tls_build_encrypted_extensions_heap(out: mut ref i64) -> i64
fn tls_build_certificate_heap(raw_pubkey: mut ref i64, out: mut ref i64) -> i64
fn tls_build_certificate_verify_heap(sig: mut ref i64, out: mut ref i64) -> i64
fn tls_build_finished_heap(verify_data: mut ref i64, out: mut ref i64) -> i64
fn tls_certverify_signed_content_heap(transcript_hash: mut ref i64, out: mut ref i64) -> i64

fn tls_hash_transcript_heap(transcript: mut ref i64, transcript_len: i64) -> [u8; 32]
fn tls_derive_secret_heap(secret: mut ref i64, label: Str, transcript: mut ref i64, transcript_len: i64) -> [u8; 32]
fn tls_finished_verify_data_heap(traffic_secret: mut ref i64, transcript: mut ref i64, transcript_len: i64) -> [u8; 32]

fn tls_encrypt_record_heap(key: mut ref i64, static_iv: mut ref i64, seq: u32, content: mut ref i64, content_len: i64, content_type: u32, out_record: mut ref i64) -> i64
fn tls_decrypt_record_heap(key: mut ref i64, static_iv: mut ref i64, seq: u32, rec_data: mut ref i64, record_len: i64, expected_content_type: u32, out_content: mut ref i64) -> i64
```

`tls_hmac_sha256`/`tls_hkdf_extract`/`tls_hkdf_expand`/`tls_hkdf_
expand_label`/`tls_derive_traffic_keys`/`tls_record_nonce`/`tls_
basepoint32`/`tls_bytes_equal32` are reused as-is from the array API
above for the heap-native functions too -- HMAC/HKDF/key-schedule
operations always work on small, bounded 12-32-byte values (keys,
IVs, digests) regardless of a board's own overall record-size ceiling.

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

The heap-pointer API has no standalone `test/host_test.vani` coverage
of its own: `buf_read_byte`/`buf_write_byte` are `extern "C"` with no
implementation in this package (a real consumer supplies them), so
neither the LLVM JIT (`vanic run`, default) nor the C backend (blocked
by gap #5 above regardless) can link a self-contained test. Verified
instead via a standalone host probe (LLVM IR emission → `llc` → `cc`
→ native execution, bypassing both blockers) cross-checking every
`_heap` function against its array-API counterpart for identical
inputs, plus a 1200-byte record round trip and tamper-rejection check
beyond the array API's own 512-byte reach -- not committed to this
repo (host-specific scratch, not portable), but reproducible the same
way. Real, permanent verification is DhruvaOS's own Pi 1 kernel
consuming this API directly, exercised by its live `tlsecho`/
`httpecho`/`mqttecho` traffic under `test/phase4_milestone.py`.
