# PostgreSQL backend for key-value storage

This module provides a PostgreSQL-backed implementation of `KeyValueStorage` for the key-value storage system. Key-value pairs are stored in a single table with the value content stored as binary data (BYTEA) to ensure safe storage of arbitrary binary content.

## Features

- Stores key-value pairs in a configurable table (`key` primary key, `value` as binary)
- Safe parameter binding via `sqlx`

## Quick start (with Docker)

Use the provided helper scripts to spin up a local PostgreSQL for development:

```bash
bash set-up.sh
```

What it does:
- Starts a container named `postgres` on host port `6432`
- Uses `POSTGRES_HOST_AUTH_METHOD=trust` for local, non-production convenience
- Runs `set-up.sql` inside the container to create the key-value table

Teardown:
```bash
docker stop policy-postgres && docker rm policy-postgres
```

## Configuration

`PostgresClient::new` accepts a `Config` with the following fields and defaults:

- `db` (default: `postgres`)
- `username` (default: `postgres`)
- `password` (optional)
- `port` (default: `5432`)
- `host` (default: `localhost`)
- `table` (default: `key_value`)

Connection string format constructed internally:
`postgresql://username[:password]@host:port/db`

If `POSTGRES_URL` env is set with postgres connection URI, use it instead of the config.

## TLS

`sqlx` is built with the `tls-rustls-ring-webpki` feature (rustls with the
ring provider and WebPKI roots), so `verify-full` connections are supported.
To require a verified connection, pass the TLS parameters through
`POSTGRES_URL`:

```text
postgresql://user@host:5432/db?sslmode=verify-full&sslrootcert=/path/to/ca.crt
```

Notes:

- SQLx parses the URL directly, including normal certificate paths such as
  `/run/db-certs/ca.crt`.
- `sslrootcert` adds the given CA to the bundled WebPKI root set; it does not
  restrict trust to it. A server certificate chaining to any publicly trusted
  CA still verifies under `verify-full`, so exclusive private-CA trust needs
  network-level controls as well.
- With `sslmode=verify-full`, SQLx refuses servers that do not offer TLS and
  rejects wrong CAs and hostnames. Without an explicit `sslmode` the SQLx
  `prefer` default attempts TLS and falls back to plaintext when the handshake
  fails; do not rely on it for confidentiality.
- The ignored test `tests/postgres_tls.rs` checks against disposable local
  clusters that a correct CA and hostname connect, wrong CAs and hostnames are
  refused (asserting the certificate-refusal errors, not just any failure),
  and `verify-full` never falls back to plaintext.

## Testing

There is an ignored async test that demonstrates end-to-end usage. To run it locally:

```bash
# ensure the database is running (e.g., via set-up.sh)
cargo test --package key-value-storage --lib -- postgres::tests::test_postgres_client --exact --show-output --ignored
```

Alternatively, run your regular test suite after ensuring a reachable PostgreSQL namespace matching your `Config`.
