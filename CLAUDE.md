# CLAUDE.md

Behavioral guidelines to reduce common LLM coding mistakes. Merge with project-specific instructions as needed.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.

---

## Project: QUIC-over-asio MVP (ngtcp2 + GnuTLS + boost::asio)

### Architecture

```
QuicClient ──► QuicSession (ngtcp2_conn + gnutls_session)
                  │
QuicServer ──► QuicSession map (keyed by SCID)
```

- **Service/Instance pattern**: `QuicServer` manages a `boost::asio::ip::udp::socket` and
  dispatches packets to the correct `QuicSession`. `QuicClient` holds one session.
- **Proactor callback mode**: All I/O is async via `boost::asio`. Retransmission uses
  `boost::asio::steady_timer`. UDP send goes through a capture lambda bound to the
  owner's socket.
- **TLS**: `quic_crypto.cpp` wraps GnuTLS init, cert loading, and session creation.
  Sessions are configured via `ngtcp2_crypto_gnutls_configure_{client,server}_session`.

### Build

```sh
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release && cmake --build . -j$(nproc)
```

Dependencies (system packages):
- libngtcp2-dev, libngtcp2-crypto-gnutls-dev
- libgnutls28-dev
- libboost-system-dev
- libgtest-dev (or googletest source at /usr/src/googletest)

### Run

```sh
# Terminal 1 — server
./build/quic_server certs/cert.pem certs/key.pem 0.0.0.0 8443

# Terminal 2 — client
./build/quic_client 127.0.0.1 8443 certs/cert.pem
```

### Run tests

```sh
cd /root/unp && ./build/quic_tests
```

All 18 tests pass.

### Key ngtcp2 v1.22.90 gotchas

- **`ngtcp2_conn_set_tls_native_handle(conn, session)` is mandatory** after
  `ngtcp2_conn_{client,server}_new`. Without it, `ngtcp2_conn_get_tls_native_handle`
  returns null and the crypto callbacks crash.
- **`schedule_timer()` must be called after `on_packet()`** — `ngtcp2_conn_read_pkt`
  may arm the loss detection timer; without re-scheduling, retransmissions never fire
  and the connection stalls when packets are lost.
- **Timer delay must have a floor (~100us)** — a 0-delay timer causes `io.poll()` loops
  to starve receive handlers (timer always ready, constantly re-arms).
- **`ngtcp2_path_storage_init` deep-copies addresses** into an internal buffer.
  Local/stack addresses are safe to pass — they're copied immediately.
- **Server `original_dcid_present`**: Server transport params MUST set
  `params.original_dcid_present = 1` and `params.original_dcid = dcid` (client's SCID
  from the Initial packet), or ngtcp2 asserts.
- **Server `dcid`/`scid` semantics**: `ngtcp2_conn_server_new(dcid, scid, ...)` —
  `dcid` = client's SCID from Initial; `scid` = server-chosen CID.
- **Client MUST have credentials set on the GnuTLS session** even without a client
  cert. Without `gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred)`,
  GnuTLS silently suppresses the TLS 1.3 Supported Versions extension, the server
  can't negotiate TLS 1.3, and the handshake fails with
  `GNUTLS_E_NO_CIPHER_SUITES`.
- **`create_server_session(nullptr)` must return nullptr** — add an early `if (!cred)
  return nullptr;` guard, otherwise `gnutls_credentials_set` on null cred produces
  an invalid session.

### Source layout

```
src/quic_crypto.hpp/cpp    — GnuTLS init, cert loading, session factory
src/quic_session.hpp/cpp   — ngtcp2_conn wrapper (one per connection)
src/quic_client.hpp/cpp    — UDP socket + QuicSession (client side)
src/quic_server.hpp/cpp    — UDP socket + session map (server side)
src/main_client.cpp        — client entry point
src/main_server.cpp        — server entry point
tests/test_quic.cpp        — Google Test suite (18 tests)
certs/cert.pem, key.pem    — self-signed X.509 for testing
docs/design.md             — architecture and design decisions
docs/implementation.md     — step-by-step implementation guide
docs/test_report.md        — test coverage and results
```
