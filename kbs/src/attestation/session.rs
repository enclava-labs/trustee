// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use actix_web::cookie::{
    time::{Duration, OffsetDateTime},
    Cookie,
};
use anyhow::{bail, ensure, Context, Result};
use kbs_types::{Challenge, Request};
use key_value_storage::{KeyValueStorage, SetParameters, SetResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::warn;
use uuid::Uuid;

pub(crate) static KBS_SESSION_ID: &str = "kbs-session-id";

/// Finite State Machine model for RCAR handshake
#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) enum SessionStatus {
    Authed {
        request: Request,
        challenge: Challenge,
        id: String,
        #[serde(with = "time::serde::rfc3339")]
        timeout: OffsetDateTime,
    },

    Attested {
        token: String,
        request_fingerprint: String,
        id: String,
        #[serde(with = "time::serde::rfc3339")]
        timeout: OffsetDateTime,
    },
}

macro_rules! impl_member {
    ($attr: ident, $typ: ident) => {
        pub fn $attr(&self) -> &$typ {
            match self {
                SessionStatus::Authed { $attr, .. } => $attr,
                SessionStatus::Attested { $attr, .. } => $attr,
            }
        }
    };
}

impl SessionStatus {
    pub fn auth(request: Request, timeout: i64, challenge: Challenge) -> Self {
        let id = Uuid::new_v4().as_simple().to_string();

        let timeout = OffsetDateTime::now_utc() + Duration::minutes(timeout);

        Self::Authed {
            request,
            challenge,
            id,
            timeout,
        }
    }

    pub fn cookie<'a>(&self) -> Cookie<'a> {
        match self {
            SessionStatus::Authed { id, timeout, .. } => Cookie::build(KBS_SESSION_ID, id.clone())
                .expires(*timeout)
                .finish(),
            SessionStatus::Attested { id, timeout, .. } => {
                Cookie::build(KBS_SESSION_ID, id.clone())
                    .expires(*timeout)
                    .finish()
            }
        }
    }

    impl_member!(id, str);
    impl_member!(timeout, OffsetDateTime);

    pub fn is_expired(&self) -> bool {
        *self.timeout() < OffsetDateTime::now_utc()
    }

    /// Idempotent completion only applies to the same evidence and public key.
    pub fn completed_token(&self, fingerprint: &str) -> Result<Option<&str>> {
        match self {
            Self::Attested {
                token,
                request_fingerprint,
                ..
            } => {
                ensure!(
                    request_fingerprint == fingerprint,
                    "attestation request differs from completed session"
                );
                Ok(Some(token))
            }
            Self::Authed { .. } => Ok(None),
        }
    }
}

// Unknown versions fail closed; callers must start a new handshake.
#[derive(Serialize, Deserialize)]
#[serde(tag = "version", content = "state")]
enum StoredSession {
    #[serde(rename = "1")]
    V1(SessionStatus),
}

fn encode(session: &SessionStatus) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&StoredSession::V1(session.clone()))?)
}

fn decode(bytes: &[u8]) -> Result<SessionStatus> {
    let StoredSession::V1(session) = serde_json::from_slice(bytes)?;
    Ok(session)
}

/// Sort object keys so whitespace/key ordering does not change retry identity.
/// String-valued evidence is kept byte-exact, as passed to the verifier.
pub fn request_fingerprint(request: &kbs_types::Attestation) -> Result<String> {
    let mut value = serde_json::to_value(request)?;
    value.sort_all_objects();
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&value)?)))
}

#[derive(Debug)]
pub(crate) struct SessionSnapshot {
    pub status: SessionStatus,
    bytes: Vec<u8>,
}

#[derive(Clone)]
pub(crate) struct SessionMap {
    pub storage: Arc<dyn KeyValueStorage>,
}

impl SessionMap {
    pub fn new(storage: Arc<dyn KeyValueStorage>) -> Self {
        SessionMap { storage }
    }

    pub async fn insert(&self, session: SessionStatus) -> Result<()> {
        ensure!(!session.is_expired(), "session expired");
        let result = self
            .storage
            .set(
                session.id(),
                &encode(&session)?,
                SetParameters { overwrite: false },
            )
            .await?;
        ensure!(
            matches!(result, SetResult::Inserted),
            "session already exists"
        );
        Ok(())
    }

    pub async fn get(&self, session_id: &str) -> Result<Option<SessionSnapshot>> {
        let Some(bytes) = self.storage.get(session_id).await? else {
            return Ok(None);
        };
        let session = decode(&bytes)?;
        ensure!(session.id() == session_id, "session ID mismatch");
        if session.is_expired() {
            return Ok(None);
        }
        Ok(Some(SessionSnapshot {
            status: session,
            bytes,
        }))
    }

    pub async fn complete(
        &self,
        expected: &SessionSnapshot,
        fingerprint: &str,
        token: String,
    ) -> Result<SessionStatus> {
        ensure!(
            !expected.status.is_expired(),
            "session expired during verification"
        );
        let SessionStatus::Authed { id, timeout, .. } = &expected.status else {
            bail!("session already completed")
        };
        let completed = SessionStatus::Attested {
            token,
            request_fingerprint: fingerprint.to_owned(),
            id: id.clone(),
            timeout: *timeout,
        };
        // Compare the entire prior record; update-if-present cannot prevent
        // concurrent attestations from overwriting each other's token/binding.
        self.storage
            .compare_and_swap(id, &expected.bytes, &encode(&completed)?)
            .await?;
        let winner = self
            .get(id)
            .await?
            .context("session disappeared or expired during completion")?;
        ensure!(
            winner.status.completed_token(fingerprint)?.is_some(),
            "session changed during completion"
        );
        Ok(winner.status)
    }

    pub async fn cleanup_expired(&self) -> Result<()> {
        // ponytail: full namespace scan, matching upstream; use indexed expiry
        // cleanup if measured session volume makes this sweep expensive.
        let mut malformed = 0;
        for key in self.storage.list().await? {
            let Some(value) = self.storage.get(&key).await? else {
                continue;
            };
            let Ok(session) = decode(&value) else {
                malformed += 1;
                continue;
            };
            // Deny at expiry, but allow one minute of clock skew before a
            // replica removes another replica's session. Expiry is immutable.
            if *session.timeout() + Duration::seconds(60) < OffsetDateTime::now_utc() {
                self.storage.delete(&key).await?;
            }
        }
        if malformed > 0 {
            warn!(
                malformed,
                "undecodable session rows retained; check session format compatibility"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use kbs_types::Tee;
    use key_value_storage::memory::MemoryKeyValueStorage;
    use serde_json::json;

    use super::*;

    #[tokio::test]
    async fn test_session_map_insert_and_get() {
        let storage = Arc::new(MemoryKeyValueStorage::default());
        let session_map = SessionMap::new(storage);
        let request = Request {
            version: "1.0.0".to_string(),
            tee: Tee::Sample,
            extra_params: json!({}),
        };
        let challenge = Challenge {
            nonce: "1234567890".to_string(),
            extra_params: json!({}),
        };
        let session = SessionStatus::auth(request, 60, challenge);
        session_map.insert(session.clone()).await.unwrap();
        let session_get = session_map.get(session.id()).await.unwrap().unwrap();

        // The kbs_types::Challenge and kbs_types::Request does not handle PartialEq
        // so we need to compare the debugging string directly.
        assert_eq!(format!("{session:?}"), format!("{:?}", session_get.status));
    }
    fn pending() -> SessionStatus {
        SessionStatus::auth(
            Request {
                version: "0.4.0".into(),
                tee: Tee::Sample,
                extra_params: json!({}),
            },
            1,
            Challenge {
                nonce: "fresh-nonce".into(),
                extra_params: json!({}),
            },
        )
    }

    async fn exercise_replicas(a: SessionMap, b: SessionMap) {
        let initial = pending();
        a.insert(initial.clone()).await.unwrap();
        assert!(b.insert(initial.clone()).await.is_err());
        let expected = a.get(initial.id()).await.unwrap().unwrap();
        let peer = b.get(initial.id()).await.unwrap().unwrap();
        // Both replicas begin with the same Authed record and produce distinct tokens.
        let (first, second) = tokio::join!(
            a.complete(&expected, "same-evidence-and-key", "token-A".into()),
            b.complete(&peer, "same-evidence-and-key", "token-B".into()),
        );
        let first = first.unwrap();
        let second = second.unwrap();
        assert_eq!(
            first.completed_token("same-evidence-and-key").unwrap(),
            second.completed_token("same-evidence-and-key").unwrap()
        );
        assert!(b
            .complete(&peer, "other-key", "attacker-token".into())
            .await
            .is_err());
        assert!(b
            .get(initial.id())
            .await
            .unwrap()
            .unwrap()
            .status
            .completed_token("other-evidence")
            .is_err());
        a.storage.delete(initial.id()).await.unwrap();
        assert!(b
            .complete(&peer, "same-evidence-and-key", "late-token".into())
            .await
            .is_err());
        assert!(b.get(initial.id()).await.unwrap().is_none());

        // A valid prior row need not match this binary's serialization: retain
        // the bytes read from storage, including whitespace/unknown fields.
        let prior = pending();
        let mut encoded: serde_json::Value =
            serde_json::from_slice(&encode(&prior).unwrap()).unwrap();
        encoded["future_metadata"] = json!("ignored-by-v1");
        let raw = serde_json::to_vec_pretty(&encoded).unwrap();
        a.storage
            .set(prior.id(), &raw, SetParameters::default())
            .await
            .unwrap();
        let snapshot = b.get(prior.id()).await.unwrap().unwrap();
        assert_ne!(snapshot.bytes, encode(&snapshot.status).unwrap());
        b.complete(&snapshot, "fp", "token".into()).await.unwrap();
        a.storage.delete(prior.id()).await.unwrap();

        let competing = pending();
        a.insert(competing.clone()).await.unwrap();
        let competing_snapshot = a.get(competing.id()).await.unwrap().unwrap();
        let (first, second) = tokio::join!(
            a.complete(&competing_snapshot, "key-A", "token-A".into()),
            b.complete(&competing_snapshot, "key-B", "token-B".into()),
        );
        assert_ne!(first.is_ok(), second.is_ok());
        a.storage.delete(competing.id()).await.unwrap();
    }

    #[tokio::test]
    async fn replicas_complete_atomically_and_deny_mismatches() {
        let storage = Arc::new(MemoryKeyValueStorage::default());
        exercise_replicas(SessionMap::new(storage.clone()), SessionMap::new(storage)).await;
    }

    #[tokio::test]
    async fn expiry_corruption_and_unknown_versions_fail_closed() {
        let storage = Arc::new(MemoryKeyValueStorage::default());
        let map = SessionMap::new(storage.clone());
        let mut session = pending();
        if let SessionStatus::Authed { timeout, .. } = &mut session {
            *timeout = OffsetDateTime::now_utc() - Duration::seconds(1);
        }
        storage
            .set(
                session.id(),
                &encode(&session).unwrap(),
                SetParameters::default(),
            )
            .await
            .unwrap();
        assert!(map.get(session.id()).await.unwrap().is_none());
        assert!(map
            .complete(
                &SessionSnapshot {
                    status: session.clone(),
                    bytes: encode(&session).unwrap()
                },
                "fp",
                "token".into()
            )
            .await
            .is_err());
        for bytes in [
            b"not JSON".as_slice(),
            br#"{"version":"2","state":{}}"#.as_slice(),
        ] {
            storage
                .set("bad", bytes, SetParameters { overwrite: true })
                .await
                .unwrap();
            assert!(map.get("bad").await.is_err());
        }
        storage
            .set(
                "wrong-id",
                &encode(&pending()).unwrap(),
                SetParameters::default(),
            )
            .await
            .unwrap();
        assert!(map.get("wrong-id").await.is_err());
        map.cleanup_expired().await.unwrap();
        assert!(storage.get(session.id()).await.unwrap().is_some());
        let mut expired = session.clone();
        if let SessionStatus::Authed { timeout, .. } = &mut expired {
            *timeout -= Duration::seconds(60);
        }
        storage
            .set(
                expired.id(),
                &encode(&expired).unwrap(),
                SetParameters { overwrite: true },
            )
            .await
            .unwrap();
        map.cleanup_expired().await.unwrap();
        assert!(storage.get(expired.id()).await.unwrap().is_none());
    }

    #[tokio::test]
    #[ignore = "requires dedicated PostgreSQL and kbs_protocol_session table; see shared-sessions.md"]
    async fn postgres_sessions_survive_client_replacement() {
        use key_value_storage::postgres::{Config, PostgresClient};
        std::env::var("POSTGRES_URL").expect("use a dedicated test database");
        let a = Arc::new(
            PostgresClient::new(Config::default(), "kbs_protocol_session")
                .await
                .unwrap(),
        );
        let b = Arc::new(
            PostgresClient::new(Config::default(), "kbs_protocol_session")
                .await
                .unwrap(),
        );
        exercise_replicas(SessionMap::new(a.clone()), SessionMap::new(b)).await;
        let session = pending();
        SessionMap::new(a.clone())
            .insert(session.clone())
            .await
            .unwrap();
        drop(a);
        let restarted = Arc::new(
            PostgresClient::new(Config::default(), "kbs_protocol_session")
                .await
                .unwrap(),
        );
        let map = SessionMap::new(restarted);
        let restored = map.get(session.id()).await.unwrap().unwrap();
        map.complete(&restored, "fp", "token".into()).await.unwrap();
        map.storage.delete(session.id()).await.unwrap();
    }
}
