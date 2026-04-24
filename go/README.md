# go/ — MiLog's Go side

Scaffolding for Phase 5. The bash `milog.sh` bundle stays the primary
artifact for the foreseeable future; this directory hosts additive Go
binaries that cover what bash can't (long-lived HTTP connections,
per-request histograms, inotify-based log tailing).

## Layout

```
go/
├── go.mod
├── cmd/
│   └── milog-web/             # HTTP daemon (foundation; SSE lands next)
│       └── main.go
└── internal/
    └── config/                # env-var config, matches bash MILOG_* vars
        ├── config.go
        └── config_test.go
```

All code is stdlib-only today. Third-party deps are introduced when the
feature that needs them lands (HDR histogram, eBPF loader, etc.) — not
preemptively.

## Build

`build.sh` at the repo root picks this up automatically when a Go
toolchain is available:

```bash
bash build.sh
# → built milog.sh (…)
# → built go/bin/milog-web (version abc1234)
```

If `go` isn't on `$PATH`, build.sh skips the Go step with a warning and
`milog.sh` still ships correctly. Users without Go lose no functionality
yet — the bash `milog web` remains the default.

## Run

```bash
go/bin/milog-web
# → listening on http://127.0.0.1:8765
curl http://127.0.0.1:8765/healthz    # → "ok"
curl http://127.0.0.1:8765/            # → scaffolding placeholder
```

Env vars (mirror the bash side):

| Var               | Default         |
| ----------------- | --------------- |
| `MILOG_WEB_BIND`  | `127.0.0.1`     |
| `MILOG_WEB_PORT`  | `8765`          |
| `MILOG_LOG_DIR`   | `/var/log/nginx` |

## Test

```bash
cd go && go vet ./... && go test ./...
```

## What's here vs what's coming

**Today (Phase 5 foundation):**
- `/healthz` liveness probe
- `/` placeholder root (prints resolved config)
- Graceful shutdown on SIGINT / SIGTERM
- Version stamped via `-ldflags "-X main.buildVersion=…"`

**Next (Phase 5 chunks, tracked in plan.md):**
- SSE `/api/stream` for live summary push (replaces the 3s poll loop)
- `/api/histogram/<app>` — HDR histogram per-request, p50/p95/p99/p99.9
- `/api/logs/stream` — SSE live log tail with filters
- `/metrics` — Prometheus plaintext format
- `milog-tui` — second Go binary, panel-based TUI (bubbletea)

**Intentionally NOT here:** any bash functionality that already works.
Per the multi-language principle in `plan.md`: Go is additive, never
substitutive. `milog monitor` / `milog alert` / `milog search` etc. stay
bash forever. Only things bash literally can't do well (long-lived HTTP,
per-request math, kernel bytecode) migrate.

## Why stdlib-only today

Every module dep is a future supply-chain surface area and a CI knot. The
Go stdlib covers `net/http` + `encoding/json` + `os/signal` + `strings`
— everything this scaffold needs. When the HDR histogram lands,
`github.com/HdrHistogram/hdrhistogram-go` joins. When eBPF work starts,
`github.com/cilium/ebpf`. Not before.
