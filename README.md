# ruleset

A self-hosted rule subscription manager. Manage multiple independent rule sets through a
web UI or a REST API, and expose each rule set as a plain-text URL for your client to
subscribe to.

## Features

- Multiple independent rule sets: create, rename, delete, and edit rules per set.
- Each rule set gets a public plain-text URL (`GET /r/{slug}`), one rule per line as
  `TYPE,value`.
- Optional per-rule-set read key: the subscription URL then requires `?k=<key>`, and
  requests without it get `404` (existence is hidden).
- Bearer-token protected management API (`ADMIN_TOKEN`), compared in constant time.
- Request body size limit, atomic persistence (temp file + rename), automatic reload at
  startup.
- The management UI is a React single-page app, built into `frontend/dist` and served by
  the same binary — deploy as one process.

## Build

```bash
# backend
cargo build --release

# frontend (requires Node.js >= 20)
cd frontend
npm install
npm run build
```

## Run

```bash
./target/release/ruleset
```

On first start, if `ADMIN_TOKEN` is not set, a random token is generated and printed to the
log (it changes on every restart). Set `ADMIN_TOKEN` to a fixed value for a permanent
deployment.

### Environment variables

| Variable      | Default            | Description                                             |
| ------------- | ------------------ | ------------------------------------------------------- |
| `BIND_ADDR`   | `0.0.0.0:3500`     | Listen address.                                         |
| `ADMIN_TOKEN` | auto-generated     | Bearer token required for all management endpoints.     |
| `DATA_FILE`   | `rulesets.json`    | Persistence file (created on first change).             |
| `FE_DIR`      | `frontend/dist`    | Directory with the built web UI.                        |
| `RUST_LOG`    | `info`             | Log level, e.g. `RUST_LOG=debug`.                       |

## Docker

The image is a static musl binary on a tiny Alpine runtime, built multi-stage (Node
frontend → Rust stage using [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild)
for musl — no emulated compilation → Alpine runtime) and pushed to Docker Hub
(`docker.io/<dockerhub-user>/ruleset`). CI builds `amd64` and `arm64` in two parallel jobs
on native runners, each publishing its own platform tag (`-amd64` / `-arm64`):

- `:latest-amd64`, `:latest-arm64` (branch/tag pushes outside PRs)
- `:v0.2.0-amd64`, `:v0.2.0-arm64` (on `v*` tag pushes)

The image runs as a non-root user, keeps data in `/app/data` (volume), and embeds the web UI.

```bash
docker build --build-arg ZIG_ARCH=x86_64 --build-arg TARGET_TRIPLE=x86_64-unknown-linux-musl -t ruleset .

# run with a named volume for persistence
docker run -d --name ruleset -p 3500:3500 \
  -e ADMIN_TOKEN='choose-a-strong-token' \
  -v ruleset-data:/app/data \
  <dockerhub-user>/ruleset:latest-amd64
```

## CI

GitHub Actions (`.github/workflows/ci.yml`) runs on every push/PR:
backend `fmt` + `clippy -D warnings` + `test`, frontend `build`, and a Docker build —
two parallel jobs (`linux/amd64` on `ubuntu-latest`, `linux/arm64` on the native arm64
runner `ubuntu-24.04-arm`), each a multi-stage musl build with cargo-zigbuild, pushed to
Docker Hub on `main` and on `v*` tags; PRs only build without pushing.

## API

Management endpoints require the header `Authorization: Bearer <ADMIN_TOKEN>`. Errors are
returned as JSON `{"error": "..."}`.

| Method | Path                            | Description                                |
| ------ | ------------------------------- | ------------------------------------------ |
| GET    | `/rulesets`                     | List rule sets (metadata only).            |
| POST   | `/rulesets`                     | Create a rule set `{"name", "slug"?}`.     |
| GET    | `/rulesets/{slug}`              | Rule set detail incl. rules and read key.  |
| PATCH  | `/rulesets/{slug}`              | Rename `{"name"}` / toggle `{"require_key"}`. |
| DELETE | `/rulesets/{slug}`              | Delete a rule set.                         |
| GET    | `/rulesets/{slug}/rules`        | Rules as JSON array.                       |
| POST   | `/rulesets/{slug}/rules`        | Add a rule `{"rule_type", "value"}`.       |
| DELETE | `/rulesets/{slug}/rules`        | Delete a rule (same body as POST).         |
| GET    | `/r/{slug}?k=<key>`             | **Public** plain-text subscription.        |

Example:

```bash
curl -X POST localhost:3500/rulesets -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' -d '{"name": "ads"}'
curl -X POST localhost:3500/rulesets/ads/rules -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' -d '{"rule_type": "DOMAIN-SUFFIX", "value": "example.com"}'
curl 'localhost:3500/r/ads?k=<read-key>'
# DOMAIN-SUFFIX,example.com
```

## Deployment & security notes

- The management API is the only surface that can change data; protect it with a strong
  `ADMIN_TOKEN`.
- A rule set created without a read key is readable by anyone who knows its URL. Enable the
  read key in the UI if the content must stay private (the URL then embeds the key).
- The service itself speaks plain HTTP; for public deployments terminate TLS in front
  (e.g. a reverse proxy) so the token and keys are never sent in clear text.
- `BIND_ADDR` defaults to `0.0.0.0`; bind to a specific interface when you do not want to
  expose it everywhere.

## Rule types

29 types are supported: `DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`, `DOMAIN-WILDCARD`,
`DOMAIN-REGEX`, `GEOSITE`, `IP-CIDR`, `IP-CIDR6`, `IP-SUFFIX`, `IP-ASN`, `GEOIP`,
`SRC-GEOIP`, `SRC-IP-ASN`, `SRC-IP-CIDR`, `SRC-IP-SUFFIX`, `DST-PORT`, `SRC-PORT`,
`IN-PORT`, `IN-TYPE`, `IN-USER`, `IN-NAME`, `PROCESS-PATH`, `PROCESS-PATH-REGEX`,
`PROCESS-NAME`, `PROCESS-NAME-REGEX`, `UID`, `NETWORK`, `DSCP`, `MATCH`.

Validation: `IP-CIDR`/`IP-CIDR6`/`SRC-IP-CIDR` must parse as CIDR;
`DOMAIN`/`DOMAIN-SUFFIX`/`DOMAIN-KEYWORD` must match a domain pattern;
`DST-PORT`/`SRC-PORT`/`IN-PORT` must be a `u16` or a range like `80-443`.
Other types are accepted as-is.
