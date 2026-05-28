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

### ODoH (Oblivious DoH) removed

Oblivious DoH support was stripped: deleted `oblivious_doh.go` (the ODoH config parsing + HPKE-style query encrypt/response decrypt), `XTransport.ObliviousDoHQuery`, `processODoHQuery`/`refreshODoHKey`, the ODoH target-config fetch path (`fetchODoHTargetInfo`/`_fetchODoHTargetInfo`/`fetchTargetConfigsFromWellKnown`), the per-server ODoH key-refresh state on `ServersInfo`, the `ODoHRelay` type and `Relay.ODoH` field, and the `odoh_servers` option (`SourceODoH`). All `StampProtoTypeODoH*` dispatch branches are gone; DNSCrypt anonymization relays are unaffected. This removes the ODoH crypto/wire code and an HTTP content-type path from the attack surface. The `odoh_servers` TOML key is **no longer recognized** — the strict loader rejects it, so it must be removed from existing configs (done in the shipped/example TOML).

### Offline source lists (no auto-update fetch)

Remote downloading of the `[sources]` resolver/relay lists is **disabled at the binary level** (`sources.go`, `allowSourceDownloads = false`). Sources load exclusively from their local signed cache files (`public-resolvers.md` / `relays.md` + `.minisig`); the proxy never makes outbound HTTP to fetch or refresh them — removing a network dependency and a periodic egress from a privacy resolver. The signed cache files must be present in the working directory (the loader fails closed otherwise). The test suite re-enables downloads to keep exercising the fetch paths. Upstreams are best pinned directly via `[static]` stamps (see *Recommended runtime configuration*) so resolution doesn't depend on the catalog at all.

### Transport timeouts aligned to the query budget

The HTTP transport's connection-level timeouts were left at a hardcoded 30 s
default (`DefaultTimeout`) that config never overrode — `xTransport.timeout` was
the master for the dialer's TCP-connect timeout, `ResponseHeaderTimeout` and
`ExpectContinueTimeout`, yet only `keepAlive` was wired from the TOML. The toml
`timeout` (e.g. 800 ms) is now also wired into `xTransport.timeout`
(`config_loader.go`), so the transport's connection-level timeouts reflect the
real per-query budget instead of a 30 s ceiling that was mostly shadowed by the
per-request `http.Client.Timeout` anyway.

The HTTP/2 idle health-check is **decoupled** from that budget so it doesn't
become an over-aggressive sub-second ping: `ReadIdleTimeout` 30 s → 10 s plus an
explicit 5 s `PingTimeout` (new `HTTP2ReadIdleTimeout` / `HTTP2PingTimeout`
constants). Dead keep-alive connections to DoH upstreams are now reaped in ~15 s
instead of riding the per-query timeout, without pinging idle-but-healthy
connections every 800 ms. The DNSCrypt UDP/TCP path already used
`serverInfo.Timeout` (= the toml timeout) and bootstrap DNS keeps its own 5 s
`ResolverReadTimeout` — both untouched.

### No outbound version-check or auto-update

dnscrypt-proxy v2 has no auto-update or version-announcement call, and this was
audited and confirmed for the edge build: `-version` prints the local version
string and exits, the only `http.Client` is the DoH transport (`Fetch`, used for
queries and the now-disabled source downloads), and `netprobe` is a UDP
connectivity check. Combined with *Offline source lists* above, a privacy
resolver makes **zero** discretionary outbound HTTP — only the encrypted DNS
queries themselves.

### Hot-path lock contention removed

Per-query synchronization was reduced so query throughput scales with cores instead of serializing on shared mutexes:

- **Dead plugin-globals lock removed** (`plugins.go`) — `PluginsGlobals` embeds a `sync.RWMutex` that was read-locked three times per query (query, response, logging plugin loops) but is **never write-locked** anywhere: the plugin slices are built once in `InitPluginsGlobals` before any listener starts and never reassigned (hot reload swaps each plugin's own internal state under the plugin's own lock). Those three `RLock`/`RUnlock` pairs were pure cross-core cache-line traffic and are gone from the hot path. (The startup-only reader in `InitHotReload` keeps the lock, which is why the field remains.)
- **`getOne()` no longer takes the write lock** (`serversInfo.go`) — every query selected an upstream under `ServersInfo`'s exclusive `Lock()`, serializing all queries. The default WP2 strategy's selection is read-only, so it now uses `RLock()`. The mutating `recoverDormantServers()` that used to run inline on every query was moved to a dedicated 10s maintenance goroutine (`StartProxy`), matching its existing time-gating. Estimator-based strategies keep the write lock.
- **`updateServerStats()` O(n) scan removed** (`serversInfo.go`) — it locked and linearly scanned the server list by name after every query to find a `*ServerInfo` the caller already held. It now takes the pointer directly (O(1) under the lock).

### Per-query allocation trims

- **UDP connection-pool key reuse** (`udp_conn_pool.go`) — `Get`/`Put` each called `addr.String()`, allocating the same `"ip:port"` string twice per UDP query for a stable upstream. New `GetByKey`/`PutByKey` let `exchangeWithUDPServer` format the key once.
- **ASCII `StringReverse`** (`common.go`) — reversed via `[]rune` (UTF-8 decode + extra allocation); DNS names are ASCII (enforced by `NormalizeQName`), so it now reverses bytewise. Removes an allocation from every name-filter evaluation (`pattern_matcher.go`).
- **Guarded debug log** (`proxy.go`) — `processIncomingQuery` built `(*clientAddr).String()` on every query for a debug line that is off in production; now gated behind the debug log level.
- **Precomputed EDNS0 padding** (`dnsutils.go`) — `addEDNS0PaddingIfNoneFound` built the padding hex with `strings.Repeat("58", paddingLen)` on every DoH query (EDNS0 block padding, `paddingLen` 0–63). The `"58"` run is now precomputed once to the block size and sliced from a shared backing string (byte-identical output; falls back to `strings.Repeat` only for the rare larger length, e.g. the unused local-DoH server path). Since WP2 routes the majority of traffic to DoH upstreams, this removes one allocation from the hot path per DoH query.

## Benchmarks

Before/after for the per-query patches, measured on AMD EPYC 7542 with
`GOMAXPROCS=4`, `GOAMD64=v3`, median of 3 (`go test -run '^$' -bench Perf
-benchmem -count=3`). The runnable cases live in `dnscrypt-proxy/bench_perf_test.go`
and `dnscrypt-proxy/bufpool_test.go`.

| Patch | Before | After | Δ |
|-------|-------:|------:|---|
| Plugin-globals lock removed | 64.6 ns | **6.8 ns** | **~9.5× faster** |
| `StringReverse` (`[]rune`→bytewise) | 309.7 ns, 48 B/op | **59.2 ns, 32 B/op** | **~5.2× faster** |
| Stats: O(n) name scan → pointer | 59.5 ns | **28.4 ns** | **~2.1× faster** |
| UDP pool key (`String()` ×2→×1) | 325.7 ns, 6 allocs/op | **164.2 ns, 3 allocs/op** | **~2.0× faster, ½ allocs** |
| `getOne` Lock→RLock (WP2) | 49.7 ns | **38.7 ns** | ~1.3× @4 cores* |

\* The lock-removal/RLock gains grow with core count (the exclusive-lock path
serializes every query); the 4-core figure understates the scaling benefit.

Pooled hot-path buffers (`bufpool.go`):

| Path | Before | After |
|------|--------|-------|
| UDP query buffer | 948.8 ns, 4096 B, 1 alloc | **13.8 ns, 0 B, 0 allocs** |
| Encrypted response buffer | 948.8 ns, 4096 B, 1 alloc | **13.9 ns, 0 B, 0 allocs** |
| `NewPluginsState` sessionData map | 1 map alloc/req | **0 allocs** |

## Recommended runtime configuration (load balancing)

The patched `getOne()` (see *Hot-path lock contention removed*) only takes the
parallel-friendly shared `RLock()` for the **WP2** strategy. Every other strategy
(`fastest`/`first`, `p2`, `ph`, `pN`, `random`) takes the exclusive `Lock()` and
serializes every query on a single mutex, and `lb_estimator = true` adds an O(n)
`sortByRtt` under that lock. For maximum QPS and lock-free selection on the
4-core EPYC, configure:

```toml
lb_strategy = 'wp2'      # only strategy that uses the shared RLock path
lb_estimator = false     # estimator is unused under WP2; keep it off explicitly
```

WP2 (weighted power-of-two-choices) samples two random servers per query, scores
each by RTT (70%) + success rate (30%), and routes to the better one. Versus
`fastest` (always the single lowest-RTT node) it spreads load across the anycast
upstreams (Cloudflare / Quad9 / Google), keeps every server's RTT estimate fresh,
and avoids the synchronized flip/herd jitter `fastest` exhibits when the estimator
re-sorts. The per-query selection math (2 RTT reads, a few float divisions, 2
`rand.Intn`) is negligible, and on Go ≥1.22 without `rand.Seed` the RNG is
lock-free, so the `RLock` path scales cleanly across all 4 cores. This is a pure
runtime config change (no rebuild) — applied live to the deployed instance.

**Empirical A/B (live, `127.0.0.1:5053`).** Each strategy was restarted, warmed,
then measured with an identical sequential latency probe (240 queries) and a
load test (10 s, 10 concurrent clients); `fastest`/`p2` ran with
`lb_estimator = true` (their intended mode). WP2 won on **both** axes:

| Strategy | seq p50 | seq p99 | Load QPS | NOERROR |
|----------|--------:|--------:|---------:|--------:|
| **`wp2`** (est off) | **4–5 ms** | 9 ms | **2,285** | 100% |
| `fastest` (est on) | 6 ms | 8 ms | 1,760 | 100% |
| `p2` (est on) | 6 ms | 15 ms | 1,579 | 100% |

`fastest` pins to whatever server was `inner[0]` at startup (often the 6 ms node,
not the 4 ms one), while WP2's power-of-two sampling keeps catching the
momentarily-fastest upstream — so WP2 is the lowest-latency option, not a
load-spreading compromise. The ~25–30% throughput gap is the exclusive `Lock()`
(`fastest`/`p2`) serializing selection versus WP2's shared `RLock()`. Conclusion:
WP2 is both fastest and highest-throughput here; keep it.

Since remote source downloads are disabled (see *Offline source lists*), the
upstreams are pinned by `[static]` stamp so resolution never depends on the
catalog:

```toml
[static]
  [static.'cloudflare']
  stamp = 'sdns://...'              # DoH   (extracted from the signed list)
  [static.'quad9-dnscrypt-ip4-nofilter-pri']
  stamp = 'sdns://...'              # DNSCrypt
  [static.'google']
  stamp = 'sdns://...'              # DoH
```

## Load & fuzz testing

Validated on the live service (AMD EPYC 7542, 4 vCPU, single NUMA) with
`lb_strategy = 'wp2'`, using a throwaway stdlib-only UDP client that crafts raw
DNS query packets and fires them concurrently at the local listener
(`127.0.0.1:5053`), while sampling the proxy's RSS, thread count and CPU jiffies
from `/proc` once per second.

**Methodology**

- *Load:* N concurrent workers, each on its own UDP socket, send A-record queries
  for a rotating set of ~15 domains for a fixed duration, read the reply with a
  2 s deadline, and record latency plus rcode. Counters track ok / timeout /
  error / SERVFAIL; latency percentiles are computed from all samples.
  (`cache = false`, so every query is forwarded to an upstream.)
- *Fuzz:* workers send malformed packets — pure random bytes; a valid 12-byte
  header followed by garbage with a bogus QDCOUNT; sub-header truncated packets;
  oversized (>4 KiB) packets; and a valid header with an illegal qname label —
  then a known-good query confirms liveness. The proxy must drop all garbage
  without crashing and keep answering valid queries.
- *Mixed:* load and fuzz run simultaneously to confirm malformed traffic does not
  degrade legitimate queries.

**Results**

| Scenario | Queries | OK | Timeouts | Errors | SERVFAIL | QPS | p50/p90/p99 |
|----------|--------:|---:|---------:|-------:|---------:|----:|-------------|
| Load (cold, 60 workers) | 22,286 | 22,120 | 166 (0.7%) | 0 | 0 | 1,843 | 18 / 31 / 46 ms |
| Load (warm, 50 workers) | 30,765 | 30,612 | 153 (0.5%) | 0 | 0 | 3,061 | 6.8 / 8.3 / 22 ms |
| Fuzz (3,300 malformed) | 3,300 | n/a | n/a | 0 crashes | n/a | n/a | 0 replies (all dropped) |

- QPS is upstream-bound (every query forwarded to anycast), not proxy-bound: at
  1,843 QPS the proxy used only ~0.46 of one core. The warm-run latency drop
  (p50 18 → 6.8 ms) reflects the UDP connection pool reusing warm upstream sockets.
- 0 errors / 0 SERVFAIL across ~53k legitimate queries; the ~0.5–0.7% timeouts
  were upstream UDP non-responses, not proxy faults.
- All 3,300 malformed packets were dropped at `validateQuery`/`Unpack` (0 replies,
  ~0 CPU); no panic, nil-pointer or index-out-of-range in the journal; liveness
  valid after every fuzz round.
- RSS stayed flat at ~20 MB, threads at 6–7, and the process PID was unchanged
  throughout (no crash or restart). Under the adversarial mix, legitimate queries
  were unaffected (3,061 QPS, 0 errors) while garbage was dropped concurrently.

## Building

Compiled with `GOAMD64=v3` and `CGO_ENABLED=0`, stripped and trimmed, targeting linux/amd64 (AMD EPYC Zen 2).
