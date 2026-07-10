# Proxy Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the reviewed protocol, denial-of-service, proxy privacy, and performance defects without changing the core per-connection proxy architecture.

**Architecture:** Keep runtime configuration immutable per accepted connection and retain the existing HTTP/1, HTTP/2, TLS, WebSocket, and passthrough branches. Add validation at each trust boundary, bounded buffering for untrusted protocol input, context-aware upstream handshakes, and explicit downstream failure responses.

**Tech Stack:** Go 1.26, `net/http`, `crypto/tls`, `golang.org/x/net/http2`, `golang.org/x/net/proxy`, uTLS, table-driven Go tests.

---

### Task 1: HTTP authority and hop-header correctness

**Files:**
- Modify: `mitm.go`
- Modify: `header.go`
- Modify: `mitm_internal_test.go`

- [ ] Add a failing HTTP/2 handler test proving that a stream whose authority differs from the connection target is rejected with 421 and never invokes the upstream transport.
- [ ] Add failing request/response header tests covering fixed hop-by-hop fields and fields named by the `Connection` header.
- [ ] Validate every HTTP/2 stream with `requestMatchesHostport` before interception or forwarding.
- [ ] Return 502, or 504 for deadline errors, when HTTP/2 upstream round trips fail.
- [ ] Replace proxy-only cleanup on ordinary HTTP requests and responses with RFC-compliant hop-header cleanup while preserving WebSocket and h2c upgrade fields.
- [ ] Run `go test -count=1 .` and confirm all tests pass.

### Task 2: Bound tunneled HTTP and WebSocket input

**Files:**
- Modify: `option.go`
- Modify: `runtime_config.go`
- Modify: `runtime_config_setters.go`
- Modify: `mitm.go`
- Modify: `bufconn.go`
- Modify: `interceptor.go`
- Modify: `runtime_config_test.go`
- Modify: `interceptor_test.go`

- [ ] Add failing tests for oversized tunneled HTTP headers, oversized WebSocket messages, and bounded queued WebSocket bytes.
- [ ] Add runtime configuration for maximum HTTP/1 header bytes, maximum WebSocket message bytes, maximum queued WebSocket bytes, and handshake timeout with conservative defaults.
- [ ] Parse tunneled HTTP/1 headers through a replayable bounded reader so request bodies and pipelined bytes remain available to `http.ReadRequest`.
- [ ] Apply handshake deadlines to protocol sniffing, TLS handshakes, h2c prefaces, and SOCKS5 negotiation.
- [ ] Call `SetReadLimit` on both WebSocket peers and account queued bytes until each frame is invoked or released.
- [ ] Preserve bytes already buffered after a WebSocket upgrade and release queued frames during shutdown.
- [ ] Run `go test -count=1 . ./buf` and confirm all tests pass.

### Task 3: Repair SOCKS5 negotiation and connect replies

**Files:**
- Modify: `socks5.go`
- Modify: `mitm.go`
- Modify: `socks5_test.go`

- [ ] Add failing tests for clients that do not offer no-auth, invalid reserved bytes, unsupported commands, dial failures, and write failures.
- [ ] Select no-auth only when the client offered method 0; otherwise send method 255.
- [ ] Parse the CONNECT request without sending success and validate version, reserved byte, command, address, and port.
- [ ] Send a SOCKS5 failure reply if the upstream dial fails, and send success with the bound address only after the dial succeeds.
- [ ] Run `go test -count=1 -run SOCKS .` and confirm all tests pass.

### Task 4: Make upstream proxy dialing private and cancelable

**Files:**
- Modify: `proxy_dialer.go`
- Modify: `proxy_dialer_test.go`
- Modify: `runtime_config.go`

- [ ] Add failing tests proving direct DNS uses the supplied dial context, proxy targets are not resolved locally, NO_PROXY bypasses environment proxies, stalled CONNECT handshakes cancel, and HTTPS proxy URLs establish TLS.
- [ ] Let `net.Dialer.DialContext` resolve direct destinations instead of pre-resolving one address with `ResolveTCPAddr`.
- [ ] Keep proxied destination addresses unresolved and use a logical remote address for metadata.
- [ ] Implement `DialContext` for HTTP proxy CONNECT, set connection deadlines from the context, preserve buffered tunnel bytes, and wrap HTTPS proxy connections in verified TLS.
- [ ] Validate supported proxy schemes and required hosts while building runtime configuration.
- [ ] Apply the environment proxy function per destination so NO_PROXY is honored.
- [ ] Run `go test -count=1 -run 'Proxy|Dial' .` and confirm all tests pass.

### Task 5: Remove certificate-generation amplification

**Files:**
- Modify: `keycert_pool.go`
- Modify: `mitm.go`
- Modify: `internal/cert/cert.go`
- Modify: `internal/cert/cert_test.go`
- Modify: `tls_fingerprint_test.go`

- [ ] Add failing tests showing certificate cache capacity does not control private-key generation and that virtual hosts sharing a target cannot poison each other's certificate cache entry.
- [ ] Keep the reusable RSA key pool small and independent from certificate-cache capacity; do not hold its mutex during key generation.
- [ ] Key forged certificates by normalized client SNI, falling back to the target host only when SNI is absent.
- [ ] Validate that the configured CA is a valid CA and that its private key matches its public key.
- [ ] Backdate leaf certificate validity slightly and clamp it to the signing CA validity period.
- [ ] Run `go test -count=1 . ./internal/cert` and confirm all tests pass.

### Task 6: Restore HTTP/2 throughput and safe logging

**Files:**
- Modify: `bufconn.go`
- Modify: `mitm.go`
- Modify: `logger.go`
- Modify: `logger_test.go`

- [ ] Add failing tests proving fixed-length HTTP/2 bodies are not flushed every 4 KiB and logged URLs omit userinfo, queries, and fragments.
- [ ] Increase the HTTP/2 copy buffer and flush only responses that require streaming behavior.
- [ ] Log a sanitized URL containing scheme, authority, and path only.
- [ ] Run `go test -count=1 -run 'Logger|Stream' .` and confirm all tests pass.

### Task 7: Secure defaults, dependencies, and full verification

**Files:**
- Modify: `README.md`
- Modify: `go.mod`
- Modify: `go.sum`

- [ ] Change runnable README listeners to loopback addresses and document authentication/ACL requirements for non-loopback exposure.
- [ ] Require Go 1.26.5 or newer and update vulnerable transitive modules where compatible.
- [ ] Run `gofmt` on every modified Go file.
- [ ] Run `go test -count=1 ./...`, `go test -race -count=1 ./...`, `go vet ./...`, and `govulncheck ./...`.
- [ ] Review `git diff --check`, `git status --short`, and the final diff for unrelated changes.
