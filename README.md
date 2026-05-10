# Gatekeeper

A local-first API security proxy written in Rust. Gatekeeper sits between clients and your upstream service, enforcing policy rules, rate limiting, threat intelligence feeds, and custom WASM-based logic — all before a request ever reaches your backend.

## Features

- **Reverse proxy** — Forwards allowed requests to a configurable upstream via Hyper
- **Policy engine** — TOML-defined rules that match on path, method, and user agent with prioritized block/throttle/allow actions
- **Rate limiting** — Per-IP token-bucket rate limiter with automatic eviction of stale buckets
- **WASM rules** — Extend the policy engine with custom WebAssembly modules (Wasmtime)
- **Threat intelligence** — Ingest external threat feeds to block known-bad IPs and user agents
- **Hot reload** — File-watcher on `config.toml`; rules, users, WASM modules, and threat feeds reload without downtime
- **JWT authentication** — Issue and verify tokens with role-based access control (Admin / Operator / Viewer)
- **User management** — Define users in config with Argon2-hashed passwords, or fall back to env-var credentials
- **Admin API & UI** — Embedded web dashboard for viewing stats, rules, and managing users (protected by RBAC)
- **Prometheus metrics** — OpenTelemetry-backed counters and histograms exposed at `/metrics`
- **Structured audit log** — Every request decision is logged as JSON to a configurable log file
- **Multi-node mode** — gRPC-based central/node architecture for syncing rules, heartbeats, and metrics across a fleet
- **CLI tooling** — Config validation, audit log inspection, request replay, and password hashing

## Quick Start

### Prerequisites

- Rust 1.70+ (edition 2021)
- Protobuf compiler (`protoc`) for gRPC codegen

### Build

```bash
cargo build --release
```

### Configure

1. Copy the example env file and fill in real values:

```bash
cp .env.example .env
```

| Variable | Purpose |
|---|---|
| `GATEKEEPER_JWT_SECRET` | **Required.** Secret used to sign/verify JWT tokens |
| `GATEKEEPER_ADMIN_USER` | Fallback admin username (used when no `[[users]]` in config) |
| `GATEKEEPER_ADMIN_PASS` | Fallback admin password |

2. Edit `config.toml` to define your policy rules:

```toml
[[rules]]
name = "block_scrapers"
path_contains = "/api"
user_agent_contains = ["curl", "wget"]
action = "block"
priority = 100

[[rules]]
name = "slow_login"
path_contains = "/login"
action = "throttle"
priority = 50
```

Optionally add `[[users]]`, `[[wasm_rules]]`, and `[[threat_feeds]]` sections — see below.

### Run

```bash
# Standalone mode (default) — proxy on :8080, forwarding to localhost:3000
cargo run -- run

# Custom port and upstream
cargo run -- run -p 9090 -u http://127.0.0.1:4000

# Central mode (serves rules to nodes via gRPC)
cargo run -- run -m central

# Node mode (syncs rules from a central server)
cargo run -- run -m node --central http://central-host:8081
```

## CLI Commands

| Command | Description |
|---|---|
| `run` | Start the proxy server |
| `test -f config.toml` | Validate a config file without starting the server |
| `inspect -f gatekeeper.log` | Query the audit log (filter with `--decision` or `--ip`) |
| `replay -f requests.json` | Replay recorded requests against the current policy engine |
| `hash-password -p "secret"` | Generate an Argon2 hash for use in `[[users]]` config |

## Configuration Reference

### Rules

```toml
[[rules]]
name = "rule_name"        # Unique identifier
path_contains = "/api"    # Optional: match request path
method = "POST"           # Optional: match HTTP method
user_agent_contains = ["bot"]  # Optional: match User-Agent substrings
action = "block"          # "block", "throttle", or "allow"
priority = 100            # Higher priority rules win
```

### Users

```toml
[[users]]
username = "admin"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$..."
role = "admin"   # "admin", "operator", or "viewer"
```

Generate hashes with: `cargo run -- hash-password -p "yourpassword"`

### WASM Rules

```toml
[[wasm_rules]]
name = "custom_check"
path = "rules/custom.wasm"
priority = 200
```

### Threat Feeds

```toml
[[threat_feeds]]
name = "abuse_ips"
url = "https://example.com/blocklist.txt"
refresh_secs = 3600
feed_type = "ip"
```

## Architecture

```
Client
  │
  ▼
┌──────────────────────────────────┐
│           Gatekeeper             │
│                                  │
│  1. Threat feed check            │
│  2. WASM rule evaluation         │
│  3. Policy engine (TOML rules)   │
│  4. Rate limiter (fallback)      │
│                                  │
│  ──► Allow  → forward to upstream│
│  ──► Block  → 403 Forbidden      │
│  ──► Throttle → delay + forward  │
│                                  │
│  Audit log ──► JSON log file     │
│  Metrics  ──► /metrics (Prom)    │
└──────────────────────────────────┘
  │
  ▼
Upstream Service
```

### Roles & Permissions

| Permission | Admin | Operator | Viewer |
|---|:---:|:---:|:---:|
| View stats & rules | ✓ | ✓ | ✓ |
| Manage rules | ✓ | ✓ | — |
| Reload config | ✓ | ✓ | — |
| Manage users | ✓ | — | — |

## Admin API

All admin endpoints are under `/admin/api/` and require a valid JWT (obtained via login).

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/admin/api/login` | POST | None | Authenticate and receive a JWT |
| `/admin/api/stats` | GET | Admin | Prometheus metrics snapshot |
| `/admin/api/rules` | GET | Admin | Current active rules |
| `/admin/api/rules/validate` | POST | Admin | Dry-run validation of a rule set |
| `/admin/api/reload` | POST | Admin | Hot-reload config from disk |
| `/admin/api/users` | GET | Admin | List users |
| `/admin/api/users` | POST | Admin | Create a user |
| `/admin/api/users/:username` | DELETE | Admin | Remove a user |
| `/metrics` | GET | Auth | Prometheus metrics endpoint |

## License

TBD
