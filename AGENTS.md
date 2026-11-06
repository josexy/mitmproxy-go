# AGENTS.md

## Project and Navigation

`github.com/josexy/mitmproxy-go/v2` is an embeddable MITM proxy library supporting HTTP, HTTPS, HTTP/2, h2c, WebSocket, SOCKS5, and raw TCP relay. Applications own listeners; the library handles interception, forwarding, and observation. Use `go.mod` for toolchain/dependency versions and `README.md` for public usage.

- Entry points and routing: `mitm.go`, `socks5.go`, `domain_tree.go`.
- Protocol sessions and adaptation: `http1_*`, `http2_*`, `h2c.go`, `websocket_handshake.go`.
- Upstream transport, proxy dialing, and TLS: `transport.go`, `proxy_dialer.go`, `tls_fingerprint.go`.
- Public configuration and interception: `option.go`, `runtime_config*.go`, `interceptor.go`.
- Wire metadata, timing, and observation: `http_profile.go`, `http_trace_timing.go`, `http_response_send.go`, `metadata/`.
- Certificates, buffers, and helpers: `keycert_pool.go`, `buf/`, `internal/`. Usage examples and traffic inspection: `examples/`, `examples/dumper/`.

## Change Guidelines

- Inspect workspace changes, implementation, and relevant tests first. Preserve existing modifications and keep changes focused.
- Trace shared changes across `ServeHTTP`, `ServeSOCKS5`, and `Serve`, including response delivery and cleanup. Keep protocol mechanics in sessions/transports and application behavior in interceptors/examples.
- Use `github.com/josexy/xhttp`, including its `httptest` and `httptrace` packages, for proxy HTTP code; do not mix `net/http` types. Module imports must include `/v2`.
- Preserve public APIs and defaults unless requested otherwise. Update configuration validation, tests, examples, and README together when applicable. Follow existing organization, explain non-obvious constraints, and run `gofmt` on modified Go files.
- Check local `go.work` before Go commands; it may select sibling checkouts. Use `GOWORK=off` for standalone module validation and restore the previous environment afterward. Upgrade dependencies only when required.
- Do not stage, commit, push, tag, or modify neighboring repositories unless explicitly requested.

## Core Invariants

- Keep bodies streaming with bounded buffering. Release bodies, connections, goroutines, timers, and pooled buffers on EOF, cancellation, early Close, errors, and shutdown. Preserve connection ownership and `Cleanup()` behavior.
- Keep routing, host filtering, and passthrough consistent across entry points. Upstream rewrites must preserve configured proxy/TLS policy, request semantics, and cancellation.
- Preserve HTTP/1 pipeline response order and message boundaries. HTTP/2 stream IDs and priority dependencies are connection-local; do not replay non-root dependencies across connections. Canceling one stream must leave sibling streams usable.
- Received wire metadata must not overwrite interceptor changes, restore removed headers, or bypass hop-by-hop sanitization, including WebSocket handshakes. Actual trailer order is available only after Body EOF; bodies reparsed after the first Hijack must retain the correct trailer metadata.
- Retry only when request semantics and body replayability permit it. Start attempt timing before backoff, reconnection, and writes; failures before headers still count as attempts. Ignore callbacks from previous attempts.
- Validate configuration before publishing immutable snapshots for new connections. Failed updates retain the previous configuration; existing connections retain their snapshot. Synchronize callback state and avoid invoking application callbacks under internal locks.
- Preserve deadlines, limits, and cancellation through dialing, TLS, forwarding, and observation. Shutdown must unblock pending I/O. Keep connection, attempt, and downstream-send timing distinct; report completion only when it occurs.
- Core logs must exclude credentials, sensitive headers/queries, bodies, WebSocket payloads, and private keys. Keep traffic dumping in the explicit dumper example.

## Validation

Run affected regressions first, then broaden checks to shared paths. For protocol and lifecycle changes, prefer real loopback connections covering streaming, reuse, cancellation, retries, and cleanup. Use temporary certificates, bounded waits, and explicit cleanup.

Run checks appropriate to the change from the repository root:

```bash
go test ./...
go test -race ./...
go vet ./...
go mod verify
go mod tidy -diff
git diff --check
```

When automatic fixes are needed, review `go fix --diff ./...` before `go fix ./...`, then rerun `gofmt` and affected tests.

Documentation-only changes need content, path, and diff checks; Go tests are unnecessary. Report what changed, checks performed, and unverified areas, including workspace/standalone dependency mode for Go checks. Local results do not establish remote CI success.
