# dnscrypt-proxy (edge fork)

Fork of [DNSCrypt/dnscrypt-proxy](https://github.com/DNSCrypt/dnscrypt-proxy) — Linux/amd64 only, built with `GOAMD64=v3` for AMD EPYC Zen 2.

Part of the `adguardhome-edge` stack: AGH-Edge → Unbound → dnscrypt-proxy → upstream resolvers (Cloudflare / Quad9 / Google over DNSCrypt + DoH). Stack specification and the AGH-Edge component live at [Ozy-666/AdGuardHome-edge-spec](https://github.com/Ozy-666/AdGuardHome-edge-spec).

For documentation, configuration reference, and upstream changelog see the [original repository](https://github.com/DNSCrypt/dnscrypt-proxy).

## Edge-fork changes

Changes carried in this fork on top of upstream, focused on cutting per-query GC pressure on the hot UDP path and trimming attack surface / binary size:

### Hot-path buffer pooling (`dnscrypt-proxy/bufpool.go`)

Under high QPS the per-query `make([]byte, …)` of the fixed ~4 KiB packet buffers dominated GC pressure. Two `sync.Pool`s now back the live UDP path:

- **`udpQueryBufferPool`** — inbound UDP query reads in `Proxy.udpListener`. The worker goroutine returns the buffer once `processIncomingQuery` completes.
- **`encryptedResponseBufferPool`** — the encrypted upstream UDP response read in `exchangeWithUDPServer` / `exchangeWithUDPServerViaProxy`.

Pools store `*[]byte` so the slice header isn't boxed into the interface on `Put`. **Aliasing contract:** `Decrypt` returns a fresh buffer on success but aliases its input on every error path, so a pooled buffer is only ever `Put` before `Decrypt` runs or after it succeeds — never on a `Decrypt` error (dropped to the GC instead).

| Path | Before | After |
|------|--------|-------|
| UDP query read buffer | 4096 B, 1 alloc/op | 0 B, 0 allocs/op |
| Encrypted response buffer | 4096 B, 1 alloc/op | 0 B, 0 allocs/op |

### Lazy session-data map (`dnscrypt-proxy/plugins.go`)

`NewPluginsState` unconditionally allocated a `map[string]any` per request. The map is now allocated lazily on first write via `setSessionData`; reads from a nil map are safe in Go, so configs whose active plugins never write session data pay zero map allocations per query.

| Path | Before | After |
|------|--------|-------|
| `NewPluginsState` sessionData map | 1 map alloc/req | 0 allocs/op |

### Monitoring UI removed

The embedded monitoring UI (HTTP + WebSocket + Prometheus server, ~1.3 KLOC and embedded HTML/JS assets) was removed: deleted `monitoring_ui.go`, `templates.go`, `static/`, and dropped the `github.com/gorilla/websocket` dependency. This trims attack surface and shrinks the binary by ~455 KB.

`MonitoringUIConfig` is kept as an **inert** struct only so existing configs carrying a `[monitoring_ui]` section still decode (the loader rejects unknown TOML keys). If `enabled = true` is set, the loader logs a warning that the section is ignored.

## Building

Built via `dnscrypt-update.sh` (in the parent `nginx-build` dir), which clones this fork's `edge-stable` branch and produces a `GOAMD64=v3`, `CGO_ENABLED=0`, stripped/trimmed binary, then deploys and restarts the service.
