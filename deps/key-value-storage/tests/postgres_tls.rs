// Copyright (c) 2026 Enclava Labs.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! TLS regression for the PostgreSQL backend.
//!
//! `PostgresClient` must honor the TLS parameters carried in `POSTGRES_URL`
//! (`sslmode=verify-full` and `sslrootcert`). With SQLx built without a TLS
//! backend, `sslmode=verify-full` cannot be satisfied and the SQLx default
//! (`prefer`) silently connects in plaintext, which is unacceptable for the
//! attestation-session and policy traffic this backend carries.
//!
//! The test is ignored because it needs disposable PostgreSQL clusters. See
//! `kbs/docs/shared-sessions.md` for the expected environment variables and a
//! way to provision the clusters locally.

#![cfg(feature = "postgres")]

use key_value_storage::postgres::{Config, PostgresClient, POSTGRES_URL_ENV_VAR};
use key_value_storage::{KeyValueStorage, SetParameters};

fn required_env(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} must point at the disposable test cluster"))
}

/// `PostgresClient::new` reads `POSTGRES_URL` from the environment, so the
/// test swaps it per phase. This binary contains a single test, therefore the
/// process-wide mutation cannot race other tests.
async fn connect_with(url: &str) -> key_value_storage::Result<PostgresClient> {
    std::env::set_var(POSTGRES_URL_ENV_VAR, url);
    PostgresClient::new(Config::default(), "kvs_tls_regression").await
}

/// `PostgresClient` does not implement `Debug`, ruling out
/// `Result::expect_err`.
fn expect_init_failure(
    result: key_value_storage::Result<PostgresClient>,
    context: &str,
) -> key_value_storage::KeyValueStorageError {
    match result {
        Ok(_) => panic!("{context}"),
        Err(e) => e,
    }
}

/// The storage error carries the SQLx error as a context chain; flatten it so
/// assertions can see the underlying refusal.
fn error_chain(err: &dyn std::error::Error) -> String {
    let mut parts = vec![err.to_string()];
    let mut source = err.source();
    while let Some(e) = source {
        parts.push(e.to_string());
        source = e.source();
    }
    parts.join(": ")
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL clusters (TLS and plaintext); see kbs/docs/shared-sessions.md"]
async fn postgres_verify_full_tls_is_enforced() {
    // Correct CA and hostname: verify-full must connect and round-trip data.
    let client = connect_with(&required_env("POSTGRES_URL"))
        .await
        .expect("verify-full connection with the correct CA must succeed");
    client
        .set(
            "tls-regression",
            b"payload",
            SetParameters { overwrite: true },
        )
        .await
        .expect("insert over verified TLS");
    assert_eq!(
        client.get("tls-regression").await.unwrap(),
        Some(b"payload".to_vec())
    );
    assert_eq!(
        client.delete("tls-regression").await.unwrap(),
        Some(b"payload".to_vec())
    );

    // Wrong trust anchor: the server certificate does not chain to the
    // configured root. A client that skipped certificate verification (or fell
    // back to plaintext) would connect successfully here.
    let err = expect_init_failure(
        connect_with(&required_env("POSTGRES_TLS_WRONG_CA_URL")).await,
        "verify-full must reject a server certified by another CA",
    );
    eprintln!("wrong CA refused with: {}", error_chain(&err));

    // Wrong hostname: the server certificate does not cover the name used to
    // reach it. A client that skipped hostname verification would connect
    // successfully here.
    let err = expect_init_failure(
        connect_with(&required_env("POSTGRES_TLS_WRONG_HOST_URL")).await,
        "verify-full must reject a certificate for another hostname",
    );
    eprintln!("wrong hostname refused with: {}", error_chain(&err));

    // Server without TLS: verify-full must fail loudly instead of silently
    // continuing in plaintext (the SQLx `prefer` default).
    let err = expect_init_failure(
        connect_with(&required_env("POSTGRES_TLS_NO_TLS_URL")).await,
        "verify-full must not fall back to a plaintext connection",
    );
    let message = error_chain(&err);
    assert!(
        message.to_lowercase().contains("tls"),
        "expected a TLS refusal, got: {message}"
    );
}
