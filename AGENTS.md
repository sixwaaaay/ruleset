# ruleset — Project Guide

This file is for AI coding agents working in this repository. It assumes no prior
knowledge of the project; read it fully first.

## Overview

`ruleset` is a lightweight rule-subscription management service written in Rust. It
manages multiple independent rule sets, lets you edit them through a REST API or the
bundled React single-page UI, and exposes each rule set as a plain-text subscription URL
(`GET /r/{slug}`, one `TYPE,value` per line) for clients to fetch.

- Repo: https://github.com/sixwaaaay/ruleset
- Scale: single-file backend `src/main.rs` (~900 lines incl. unit tests); frontend under
  `frontend/` (Vite + React + TypeScript). The built frontend lives in `frontend/dist`
  and is served by the same backend process, so the whole product deploys as one process.
- Data is persisted to `rulesets.json` (path overridable via env), written atomically
  (temp file + rename) and reloaded at startup.

## Tech stack

| Area | Choice |
| --- | --- |
| Language | Rust, edition 2024 (requires Rust >= 1.85) |
| Async runtime | tokio 1.x (features: `full`, `fs`) |
| Web framework | axum 0.8 (feature: `json`; path params use `{slug}` syntax) |
| Middleware | tower-http 0.6 (`compression-gzip`), custom auth middleware |
| Serialization | serde 1.0 (derive) + serde_json 1.0 |
| Validation | regex 1.x, ipnet 2.x (`IpNet::from_str` for CIDR) |
| Randomness | getrandom 0.3 (`getrandom::fill`) for tokens and read keys |
| Global state | `LazyLock<tokio::sync::Mutex<HashMap<String, Ruleset>>>` (slug → ruleset) |
| Errors | thiserror 1.x + custom `IntoResponse` |
| Logging | tracing + tracing-subscriber (`env-filter`; default info, tune via `RUST_LOG`) |
| Frontend | Vite 7 + React 19 + TypeScript (strict), no UI library |
| Dep updates | Renovate (`renovate.json`, extends `config:recommended`) |

Resolved dependency versions are in `Cargo.lock` (committed).

> History: the previously declared `validator` and `once_cell` dependencies were removed;
> `once_cell` is replaced by `std::sync::LazyLock`.

## Build & run

```bash
# backend
cargo build                 # debug
cargo build --release       # release

# frontend (Node.js >= 20)
cd frontend && npm install && npm run build   # output in frontend/dist

# run (build the frontend first, otherwise the index page shows a "not built" notice)
cargo run                   # or ./target/release/ruleset
```

- On first start a missing `rulesets.json` is silently ignored (starts empty); if the file
  exists but fails to parse, a `warn!` is logged and the service starts with no data.
- Unit tests: `cargo test` (`#[cfg(test)]` module at the bottom of `src/main.rs`).
- Lint: `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` (enforced by CI).
- Docker images: `docker build -t ruleset .` (musl, `Dockerfile`: static musl binary, Alpine
  runtime) and `docker build -f Dockerfile.glibc -t ruleset:glibc .` (glibc, Debian slim
  runtime). Both are multi-stage, run as a non-root user, and use a data volume `/app/data`.
- If no Rust toolchain is present in the environment, one can be installed repo-locally
  (`RUSTUP_HOME`/`CARGO_HOME` pointed at directories inside the repo; they are gitignored).

## Environment variables

| Variable | Default | Description |
| --- | --- | --- |
| `BIND_ADDR` | `0.0.0.0:3500` | Listen address. |
| `ADMIN_TOKEN` | auto-generated (printed to the log) | Bearer token for the management API; set it explicitly for permanent deployments. |
| `DATA_FILE` | `rulesets.json` | Data file path. |
| `FE_DIR` | `frontend/dist` | Directory with the built web UI. |

## HTTP API

Every management endpoint requires `Authorization: Bearer <ADMIN_TOKEN>`; the token is
compared in constant time. Errors are JSON `{"error": "..."}`.

| Method | Path | Description |
| --- | --- | --- |
| GET | `/rulesets` | List rule sets (metadata only). |
| POST | `/rulesets` | Create a rule set `{"name", "slug"?}`; duplicate name → 409. |
| GET | `/rulesets/{slug}` | Rule set detail (rules and read key). |
| PATCH | `/rulesets/{slug}` | Rename `{"name"}` / toggle read protection `{"require_key": true/false}`. |
| DELETE | `/rulesets/{slug}` | Delete a rule set. |
| GET | `/rulesets/{slug}/rules` | Rules as JSON array. |
| POST | `/rulesets/{slug}/rules` | Add a rule `{"rule_type", "value"}`; duplicate → 409. |
| DELETE | `/rulesets/{slug}/rules` | Delete a rule (same body as POST); missing → 404. |
| GET | `/r/{slug}?k=<key>` | **Public** plain-text subscription endpoint (no token). |

Notes:

- `slug` derives from the name or a provided value (lowercase alphanumerics + hyphens) and
  is immutable after creation; collisions get a `-2`, `-3`, ... suffix.
- New rule sets are read-protected by default (a random 32-byte key is generated). While
  protected, `/r/{slug}` must be called with the correct `k` parameter; otherwise it
  returns 404 to hide the rule set's existence. Turning protection off removes the need.
- Unmatched requests fall through to `spa_fallback`: `/api` and `/rulesets` prefixes get a
  JSON 404; everything else is served as a static file (with path-traversal protection),
  falling back to `index.html` for extension-less paths when the file is missing.
- Request bodies are capped at 64 KiB (`DefaultBodyLimit`); all routes are gzip-compressed.

## Rule types & validation

`RuleType` has 29 variants: `DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`,
`DOMAIN-WILDCARD`, `DOMAIN-REGEX`, `GEOSITE`, `IP-CIDR`, `IP-CIDR6`, `IP-SUFFIX`,
`IP-ASN`, `GEOIP`, `SRC-GEOIP`, `SRC-IP-ASN`, `SRC-IP-CIDR`, `SRC-IP-SUFFIX`,
`DST-PORT`, `SRC-PORT`, `IN-PORT`, `IN-TYPE`, `IN-USER`, `IN-NAME`, `PROCESS-PATH`,
`PROCESS-PATH-REGEX`, `PROCESS-NAME`, `PROCESS-NAME-REGEX`, `UID`, `NETWORK`, `DSCP`,
`MATCH`.

- JSON (de)serialization uses `#[serde(rename_all = "SCREAMING-KEBAB-CASE")]`, so requests
  use uppercase hyphenated strings such as `"DOMAIN-SUFFIX"`. Do not switch back to
  `UPPERCASE` — it renders multi-word types as `DOMAINSUFFIX` and breaks deserialization.
- `Rule::validate()`: `IP-CIDR`/`IP-CIDR6`/`SRC-IP-CIDR` parse with `IpNet::from_str`;
  `DOMAIN`/`DOMAIN-SUFFIX`/`DOMAIN-KEYWORD` match a domain regex; `DST-PORT`/`SRC-PORT`/
  `IN-PORT` are a `u16` or a `start-end` range; other types are accepted as-is.
- The frontend hardcodes the same 29 uppercase type strings in `frontend/src/api.ts`; keep
  it in sync when the enum changes.

## Frontend

- `frontend/` is a Vite + React 19 + TypeScript single-page app, no router: left sidebar
  lists rule sets (create/delete/select), right pane edits the selected one (rename, read
  protection toggle, subscription URL copy, rule add/delete).
- The admin token lives in `localStorage` (key `ruleset_admin_token`); a 401 clears it and
  returns to the login screen.
- Dev mode: `cd frontend && npm run dev`; vite proxies `/rulesets` and `/r` to
  `127.0.0.1:3500`.

## Code organization (src/main.rs, top to bottom)

1. Env constants and global statics (`DATA_FILE`, `FE_DIR`, `ADMIN_TOKEN`, `RULESETS`,
   `INDEX_HTML`).
2. `ApiError` (thiserror) and its `IntoResponse` (status mapping, `WWW-Authenticate` on
   401).
3. `RuleType`, `Rule` + `validate()`, `Ruleset`.
4. Request/response structs (`CreateRuleset`, `UpdateRuleset`, `RulesetSummary`,
   `RulesetDetail`).
5. Management handlers: `list_rulesets` / `create_ruleset` / `get_ruleset` /
   `update_ruleset` / `delete_ruleset` / `get_rules` / `add_rule` / `delete_rule`.
6. Public endpoint `public_ruleset` (key check + plain text output).
7. Auth middleware `require_auth` (Bearer + constant-time compare).
8. Static serving `spa_fallback` + `mime_for`.
9. Helpers (`slugify`, `unique_slug`, `generate_secret`, `constant_time_eq`, ...) and
   validators.
10. Persistence `save_rulesets` (atomic) / `load_rulesets`.
11. `main()` and the `#[cfg(test)]` test module.

## Dev conventions

- Commit messages: conventional commits style.
- Code style: no enforced rustfmt/clippy config; follow the default style. Comments should
  match the style of the surrounding code.
- Dependency changes: only add dependencies the project actually uses; commit `Cargo.lock`
  along with the change.
- CI: GitHub Actions (`.github/workflows/ci.yml`) runs backend `fmt`/`clippy -D warnings`/
  `test`, frontend `build`, and a Docker matrix (`musl` + `glibc`, each amd64 + arm64, pushed
  to Docker Hub via the `DOCKERHUB_USER`/`DOCKERHUB_TOKEN` secrets on `main` and on `v*`
  tags; PRs only build without pushing). Tag pushes also tag the images with the tag name
  (`:v0.2.0`, `:v0.2.0-glibc`).

## Security model

- Management API auth: all `/rulesets*` routes require the `ADMIN_TOKEN` Bearer token,
  compared in constant time; missing/wrong tokens get 401.
- Read protection: each rule set carries a random read key by default; the public endpoint
  requires `?k=` and otherwise 404s (existence is hidden).
- Input limits: 64 KiB body cap; rule types/domains/ports validated per type.
- Path traversal guard: static serving 404s on `..` or backslashes and never decodes then
  joins paths.
- Atomic persistence: temp file + rename, so a crash mid-write cannot corrupt the data
  file.
- Deployment advice: for public deployments set a strong `ADMIN_TOKEN`, terminate TLS at a
  reverse proxy (the token and keys must not travel in plain text), and bind to a specific
  interface via `BIND_ADDR` when appropriate.

## Known limitations

- All writes go through a single global `tokio::Mutex`; concurrent write throughput is
  limited but correct.
- No rate limiting, single shared admin token (no multi-user model).
- The old single-rule-set `rules.json` format is gone; migrate by re-entering rules via the
  new API.
