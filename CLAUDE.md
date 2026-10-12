# adns

Authoritative DNS server in Rust. Cargo workspace:

- `adns-proto` — wire format: packets, names, records, TSIG (`tsig` feature).
- `adns-zone` — `Zone` model (YAML via serde), query answering, RFC2136 update application.
- `adns-client` — small async DNS client.
- `adns-server` — library + binary. UDP/TCP server (`src/server/`), zone providers (`src/zone_provider/`: static, file, dyn_file, merge), Postgres/CockroachDB provider (`src/db/`, migrations in `migrations/`), Prometheus metrics (`src/metrics.rs`).

Zone providers implement `ZoneProvider::run`, pushing whole new `Zone`s over an mpsc channel; the server swaps them in with `ArcSwap`. Updates (RFC2136) flow back to the provider as `ZoneProviderUpdate`.

## Building on macOS

The `file_zone` feature (default) depends on `really-notify`, which is Linux-only. On macOS:

- `cargo check -p adns-server --lib --no-default-features --features postgres` works.
- The `adns-server` binary only builds with `file_zone`, so build/verify it via Docker.

## Gotchas

- **Metric labels must be bounded.** Prometheus never evicts label sets; labelling by client IP or query name (which preserves case and is attacker-controlled) leaked hundreds of MB in prod. Only use labels with a small fixed set of values (class, type, auth). Per-client detail belongs in logs.
- Query names preserve case (DNS 0x20); compare via `Name` equality / `lowercased()`, not raw strings.

## Releasing

Only bump and publish crates that changed. Inter-crate deps use `path` + `version`; bump dependents' version requirements when a dependency's minor version changes.

1. Bump `version` in the crate's `Cargo.toml`, run `cargo update -p <crate> --offline`, commit (`server vX.Y.Z` style), push to `master`.
2. Crates: `cargo publish -p <crate>` in dependency order (proto → zone → client → server); see `cargo_publish.sh`. Use `--no-verify` for `adns-server` on macOS.
3. Docker: `./publish.sh <version>` (tag without `v`, e.g. `0.3.1`). Builds `protryon/adns-server` for linux/amd64 + linux/arm64 with buildx; the Dockerfile cross-compiles with rustc on the build host (no emulation). The project is pure Rust apart from the cross linkers installed in the builder stage.
