# Shared KBS protocol sessions

KBS can keep attestation handshake sessions in PostgreSQL so that one KBS
process can answer a challenge issued by another. The default remains in-memory
sessions, including when policy/resource storage uses a different backend.

This feature is a building block for failover, **not an instruction to scale an
existing deployment**. Replicas also need consistent signed policies, ownership
resources, AS policies, reference values, and signing/TLS identities. A shared
session table does not make local resource storage safe across replicas or
prevent an old startup policy from overwriting a newer policy.

## Configuration

Set the following top-level option explicitly:

```toml
session_storage_type = "Postgres"

[storage_backend.backends.postgres]
# Connection settings can instead come from POSTGRES_URL injected as a Secret.
db = "trustee"
username = "trustee"
host = "postgres.example.internal"
port = 5432
```

Provision [the session table](../test_data/sql/sessions.sql) before starting KBS.
All replicas must connect to the same `kbs_protocol_session` table. The runtime
role needs SELECT, INSERT, UPDATE and DELETE on that table; schema creation
belongs to the migration operator. Protect database traffic, storage and backups
as security-sensitive data. The existing PostgreSQL configuration and
`POSTGRES_URL` are reused; deployments requiring distinct session and durable
resource/policy credentials need separate connection wiring before enabling HA.
Use `POSTGRES_URL` when a password is required: the inherited structured-password URL construction has a separate known limitation. No connection URL is logged by the PostgreSQL backend.

`Memory` and `Postgres` are the only supported session backends. LocalJson and
LocalFs are rejected because their storage implementations do not offer the
cross-client atomic completion required here. Missing configuration means
Memory; it does not inherit the policy storage type. Backend errors propagate,
with no fallback to an empty in-memory store.

### Transport security (TLS)

The PostgreSQL driver is built with SQLx's rustls backend (ring provider,
WebPKI roots). Deployments that require verified TLS pass the parameters in
`POSTGRES_URL`:

```text
postgresql://trustee@postgres.example.internal:5432/trustee?sslmode=verify-full&sslrootcert=/etc/trustee/ca.crt
```

SQLx parses the URL directly. Certificate contents and mount paths are
deployment-owned.
With `sslmode=verify-full`, SQLx refuses servers that do not offer TLS and
rejects wrong CAs or hostnames; without an explicit `sslmode` the SQLx
`prefer` default can silently use plaintext.

## Protocol and security

Sessions have a versioned serialization containing the challenge, immutable
expiry and, after successful verification, the attestation token plus a request
fingerprint. Unknown versions and malformed records fail closed; clients must
start a new handshake. Expired sessions are denied immediately and periodically removed after a 60-second garbage-collection grace period for clock skew. Keep replica clocks synchronized. Undecodable rows are retained with a warning so a rollback cannot delete a newer version's sessions; migration operators must clean obsolete formats after all readers are retired.

Completion uses compare-and-swap against the entire prior database row.
Concurrent identical requests receive the committed winner's token. Concurrent
or subsequent requests with different evidence, nonce, initialization data or
TEE public key are rejected without returning the stored token. JSON object
keys are sorted before hashing; string-valued evidence remains byte-exact.
Attestation tokens loaded from sessions still pass through the existing token
signature verification, signed resource-policy evaluation and encryption to the
verified TEE key before resources are released.

This fingerprint/version format is a downstream hardening adaptation; shared
session records are not interchangeable with unmodified upstream KBS records.
Do not mix upstream and fork binaries against the same session namespace.

## Rollout boundaries

First deploy guests that can safely restart failed handshakes. With the desired
replica count still one, enable PostgreSQL sessions, wait for all old Memory
pods to disappear, and verify the database path. Even that rolling update can
temporarily overlap two incompatible session stores. Do not raise the replica
count until policy publication/revocation barriers, durable resource migration,
AS/RVPS configuration consistency and readiness/drain behavior have been
validated. This change does not alter deployment replicas, resource storage,
policy publication or containerd runtime-handler configuration.

Rollback to Memory starts by scaling to one and draining surplus/old pods, then
changing the session configuration. Never roll back ownership storage to a stale
copy. Missing/expired/incompatible sessions require a new handshake; session
recovery must not become a guest's permanent error state. A database outage
still interrupts handshakes; two KBS processes do not provide database HA.

## Fork state inventory

Compared with the fork's common ancestor (`b16a4e96`), the handshake session map
is the process-local protocol authority moved by this change. The independent
receipt path in `api_server.rs` verifies evidence, signature and key binding per
request; it introduces no process-local replay/nonce registry. SNP early-binding
checks are per-evidence validation. The SNP VCEK cache is an HTTP verification-
input cache, not ownership or replay authority. Static regex/version/certificate
maps are immutable verification inputs. These remain per-process.

The resource LocalFs backend has a process-local write lock: **it is not safe to
use that lock as cross-replica ownership coordination**. Resource migration to a
backend with conditional writes remains a deployment gate. Retain signed-policy,
receipt-binding and conditional resource operation regressions, and repeat the
inventory when rebasing further fork changes. This PR does not claim a complete
multi-tenant failover rehearsal.

## Validation

```sh
cargo test --locked -p kbs --no-default-features --features coco-as-grpc --lib
```

For a dedicated disposable PostgreSQL database (never a deployment database):

```sh
export POSTGRES_URL='postgresql://test-user@localhost:5432/trustee_test'
psql "$POSTGRES_URL" -v ON_ERROR_STOP=1 -f kbs/test_data/sql/sessions.sql
cargo test --locked -p kbs --no-default-features --features coco-as-grpc \
  postgres_sessions_survive_client_replacement -- --ignored
```

The PostgreSQL test uses independent clients for competing identical and
mismatched completions, denies completion after deletion, and replaces the
issuing client before continuing the handshake. Unit tests cover expiry,
corruption, unknown versions and an HTTP auth-on-A/attest-on-B flow.

A TLS regression (`deps/key-value-storage/tests/postgres_tls.rs`, ignored)
covers `verify-full` end to end against disposable local clusters: a correct
CA and hostname connect and round-trip data, a wrong CA
(`POSTGRES_TLS_WRONG_CA_URL`) and a wrong hostname
(`POSTGRES_TLS_WRONG_HOST_URL`) are refused, and `POSTGRES_TLS_NO_TLS_URL`
proves that a server without TLS is rejected instead of silently downgraded to
plaintext. Run the disposable TLS fixture from the repository root (requires
PostgreSQL tools, OpenSSL and a non-root user):

```sh
bash deps/key-value-storage/tests/postgres_tls.sh
```

## Upstream provenance

Adapted together from confidential-containers/trustee:

- `1d403e7360fd235cf9caf90d9fa033830293fb09`: persistent sessions.
- `a1299ada05bc2b8b785e8b8e103e999d76724f21`: independent session storage selection.
- `0c1731993136707ae1860a734c338d4d570e3ddc`: expired-session cleanup.
- Session namespace correction from `d164ebf26c0a0494cce85ce129b453f451bc88af`.

Downstream adaptations preserve the default, require atomic completion, bind
idempotent retries to evidence/key, version stored records, reject non-atomic
backends, and retain the fork's receipt-evidence verification path.
