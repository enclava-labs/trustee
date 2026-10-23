// Copyright (c) 2024 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, bail, Context, Error, Result};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ear::{Algorithm, Appraisal, Ear, Extensions, RawValue, RawValueKind, VerifierID};
use jsonwebtoken::jwk;
use kbs_types::Tee;
use key_value_storage::KeyValueStorageInstance;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use policy_engine::rego::RegorusExtension;
use policy_engine::{rego::Regorus, PolicyEngine};
use serde::Deserialize;
use serde_json::{json, Value};
use serde_variant::to_variant_name;
use std::collections::{BTreeMap, HashMap};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use time::{Duration as TimeDuration, OffsetDateTime};
use tracing::{debug, info, warn};

use crate::ear_token::EarTokenConfiguration;
use crate::rvps::RvpsClient;
use crate::TeeClaims;

/// The policy claim that will hold trust claims.
pub const TRUST_CLAIMS_RULE: &str = "data.policy.trust_claims";
/// The policy claim that will hold extensions.
pub const EXTENSIONS_RULE: &str = "data.policy.extensions";

pub struct EarAttestationTokenBroker {
    config: EarTokenConfiguration,
    private_key: EcKey<Private>,
    cert_url: Option<String>,
    cert_chain: Option<Vec<X509>>,
    policy_engine: PolicyEngine<Regorus>,
}

impl EarAttestationTokenBroker {
    /// Re-assert that the shipped `default_*` policies still hold the
    /// compile-time bytes (Devin review on #17, round 3): a policy mutated in
    /// storage AFTER construction — e.g. through the policy API — would
    /// otherwise be served to `evaluate_rego` as-is, and the broker could
    /// sign appraisals with unverified rules. Identical copies are left
    /// untouched (no write); a diverged copy is restored; if the restore
    /// fails (e.g. read-only storage) the caller fails closed instead of
    /// appraising with diverged content. Custom policy ids are unaffected.
    async fn ensure_shipped_policies_authoritative(
        policy_engine: &PolicyEngine<Regorus>,
    ) -> Result<()> {
        for (policy_id, policy) in [
            ("default_cpu", include_str!("ear_default_policy_cpu.rego")),
            ("default_gpu", include_str!("ear_default_policy_gpu.rego")),
            (
                "default_switch",
                include_str!("ear_default_policy_switch.rego"),
            ),
            (
                "default_ppcie",
                include_str!("ear_default_policy_ppcie.rego"),
            ),
        ] {
            match policy_engine.get_policy(policy_id).await {
                Ok(existing) if existing == policy => continue,
                _ => {
                    warn!(
                        policy_id,
                        "stored policy diverged from the shipped default — restoring the \
                         shipped content (shipped ids are compile-time authoritative; register \
                         custom policies under their own ids)"
                    );
                    policy_engine.set_policy(policy_id, policy, true).await?;
                }
            }
        }
        Ok(())
    }

    pub async fn new(
        config: EarTokenConfiguration,
        storage: KeyValueStorageInstance,
    ) -> Result<Self> {
        // TODO: delete this warning
        warn!("Simple Token has been deprecated in v0.16.0. Note that the `attestation_token_broker` config field `type` is now ignored and the token will always be an EAR token.");

        let policy_engine = PolicyEngine::<Regorus>::new(storage);

        // The shipped defaults are compile-time content and authoritative at
        // STARTUP: overwrite must be true or a persisted copy from a previous
        // version (registration disabled overwrite) survives the upgrade and
        // bypasses any newly added rejection branches. Custom policy ids
        // registered through the API keep their own names and are unaffected.
        //
        // Registration is read-compare-write (Devin review on #17): an
        // IDENTICAL preloaded copy needs no write, so a deployment with its
        // policy store preloaded read-only starts cleanly. A differing copy is
        // still overwritten — and on read-only storage that write FAILS
        // startup: never silently serve a stale policy.
        Self::ensure_shipped_policies_authoritative(&policy_engine).await?;

        if config.signer.is_none() {
            info!("No Token Signer key in config file, create an ephemeral key and without CA pubkey cert");
            return Ok(Self {
                private_key: generate_ec_keys()?.0,
                config,
                cert_url: None,
                cert_chain: None,
                policy_engine,
            });
        }

        let signer = config.signer.clone().unwrap();
        let pem_data = std::fs::read(&signer.key_path)
            .map_err(|e| anyhow!("Read Token Signer private key failed: {:?}", e))?;
        let private_key = EcKey::private_key_from_pem(&pem_data)?;

        let cert_chain = signer
            .cert_path
            .as_ref()
            .map(|cert_path| -> Result<Vec<X509>> {
                let pem_cert_chain = std::fs::read_to_string(cert_path)
                    .map_err(|e| anyhow!("Read Token Signer cert file failed: {:?}", e))?;
                X509::stack_from_pem(pem_cert_chain.as_bytes())
                    .map_err(|_| anyhow!("Invalid PEM certificate chain"))
            })
            .transpose()?;

        Ok(Self {
            config,
            private_key,
            cert_url: signer.cert_url,
            cert_chain,
            policy_engine,
        })
    }
}

/// Extensions that will be added to the attestation token.
#[derive(Debug, Deserialize)]
pub struct TokenExtension {
    pub name: String,
    pub key: i32,
    pub value: Value,
}

#[derive(Debug)]
pub struct EvaluationResult {
    pub trust_claims: Value,
    /// Extensions to be added to the attestation token.
    pub extensions: Vec<TokenExtension>,
    pub policy_hash: String,
}

impl EarAttestationTokenBroker {
    pub async fn issue(
        &self,
        all_tee_claims: Vec<TeeClaims>,
        policy_ids: Vec<String>,
        rvps_client: Option<RvpsClient>,
    ) -> Result<String> {
        if policy_ids.len() > 1 {
            warn!("EAR token only accepts the first policy. The rest will be ignored.");
        }

        if policy_ids.is_empty() {
            bail!("No policy is given for EAR token generation.");
        }

        let mut tee_class_indices: HashMap<String, u8> = HashMap::new();
        let mut submods = BTreeMap::new();

        // Create an appraisal for each device
        for tee_claims in all_tee_claims {
            let mut appraisal = Appraisal::new();

            let tcb_claims = transform_claims(
                tee_claims.claims,
                tee_claims.init_data_claims.clone(),
                tee_claims.runtime_data_claims.clone(),
                tee_claims.tee,
                self.config.verbose_token,
            )?;

            let tcb_claims_json = serde_json::to_string(&tcb_claims)?;

            // There is a policy for each tee class.
            // The cpu tee class is loaded as the default.
            let policy_id = format!("{}_{}", policy_ids[0], tee_claims.tee_class);
            let mut extensions = vec![];
            if let Some(rvps_client) = &rvps_client {
                let rvps_client = rvps_client.clone();
                let extension = RegorusExtension {
                    name: "query_reference_value".to_string(),
                    id: 1,
                    extension: Box::new(move |params: Vec<regorus::Value>| {
                        if params.len() != 1 {
                            bail!("query_reference_value extension requires exactly one parameter");
                        }
                        let id = params[0]
                            .as_string()
                            .context("query_reference_value extension parameter must be a string")?
                            .to_string();
                        debug!("query reference value from RVPS: {id}");
                        let (tx, rx) = mpsc::channel::<Result<Option<serde_json::Value>>>();

                        let fut = async |rvps_client: RvpsClient,
                                         reference_value_id: String|
                               -> Result<_> {
                            let rv = rvps_client
                                .lock()
                                .await
                                .query_reference_value(&reference_value_id)
                                .await?;
                            Ok(rv)
                        };

                        let rvps_client = rvps_client.clone();
                        let reference_value_id = params[0].as_string()?.to_string();
                        let _ = thread::spawn(move || {
                            let rt = tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()
                                .expect("failed to build runtime");

                            let res = rt.block_on(fut(rvps_client, reference_value_id));

                            tx.send(res)
                        });

                        // We wait for 10 seconds at most.
                        match rx.recv_timeout(Duration::from_secs(10)) {
                            Ok(Ok(Some(v))) => {
                                let json_value = serde_json::to_value(v)?;
                                let value: regorus::Value = serde_json::from_value(json_value)?;
                                Ok(value)
                            }
                            Ok(Ok(None)) => {
                                warn!("No reference value found for the given id: {id}, use NULL as the returned value");
                                Ok(regorus::Value::Null)
                            }
                            Ok(Err(e)) => bail!("Get Reference Value from RVPS failed: {e:?}"),
                            Err(e) => bail!("Get Reference Value from RVPS timeout: {e:?}"),
                        }
                    }),
                };

                extensions.push(extension);
            }

            // Shipped-default authority holds at EVALUATION time too (Devin
            // review on #17, round 3): a policy mutated in storage after
            // construction is restored here, and a failed restore fails the
            // appraisal — never sign with unverified rules. Deployments that
            // legitimately reconfigure appraisal under a shipped id (e.g.
            // test harnesses) opt out via `lock_shipped_default_policies`.
            if self.config.lock_shipped_default_policies {
                Self::ensure_shipped_policies_authoritative(&self.policy_engine).await?;
            }
            let policy_results = self
                .policy_engine
                .evaluate_rego(
                    None,
                    &tcb_claims_json,
                    &policy_id,
                    vec![TRUST_CLAIMS_RULE, EXTENSIONS_RULE],
                    extensions,
                )
                .await?;

            match policy_results
                .eval_rules_result
                .get(TRUST_CLAIMS_RULE)
                .with_context(|| {
                    format!(
                        "Trust claims rule {TRUST_CLAIMS_RULE} not found for policy {policy_id}"
                    )
                })? {
                Some(value) => {
                    let trust_claims =
                        value.as_object().context("Trust claims is not an object")?;
                    for (k, v) in trust_claims {
                        let claim_value = v.as_i64().context("Trust claim value not number")?;
                        debug!("Trust claim: {}: {}", k, claim_value);

                        appraisal
                            .trust_vector
                            .mut_by_name(k)
                            .unwrap()
                            .set(claim_value as i8);
                    }
                }
                None => {
                    warn!("No trust claims found by enforcing policy {policy_id}, set all TrustVector claims to 0");
                    appraisal.trust_vector.set_all(0);
                }
            }

            if !appraisal.trust_vector.any_set() {
                bail!("At least one policy claim must be set.");
            }

            // Set extensions from policy result
            let mut extensions = Extensions::new();
            let extension_claims = policy_results
                .eval_rules_result
                .get(EXTENSIONS_RULE)
                .context("Extensions rule not found")?
                .as_ref()
                .cloned()
                .unwrap_or(json!([]));

            let extension_claims =
                serde_json::from_value::<Vec<TokenExtension>>(extension_claims.clone())?;
            for extension in extension_claims {
                let extension_value: RawValue =
                    serde_json::from_str(&serde_json::to_string(&extension.value)?)?;

                extensions.register(&extension.name, extension.key, extension_value.kind())?;
                extensions.set_by_name(&extension.name, extension_value)?;
            }

            appraisal.extensions = extensions;

            appraisal.annotated_evidence = tcb_claims;
            appraisal.policy_id = Some(policy_ids[0].clone());
            appraisal.update_status_from_trust_vector();

            if let Some(index) = tee_class_indices.get_mut(&tee_claims.tee_class) {
                *index += 1;
            } else {
                tee_class_indices.insert(tee_claims.tee_class.clone(), 0);
            }

            let submod_name = format!(
                "{}{}",
                tee_claims.tee_class,
                // We know this key will exist because of the logic above.
                tee_class_indices.get(&tee_claims.tee_class).unwrap()
            );
            submods.insert(submod_name, appraisal);
        }

        let now = OffsetDateTime::now_utc();
        let exp = now
            .checked_add(TimeDuration::minutes(self.config.duration_min))
            .ok_or(anyhow!("Token expiration overflow."))?;

        let mut extensions = Extensions::new();
        extensions.register("exp", 4, RawValueKind::Integer)?;
        extensions.set_by_name("exp", RawValue::Integer(exp.unix_timestamp()))?;

        let ear = Ear {
            profile: self.config.profile_name.clone(),
            iat: now.unix_timestamp(),
            vid: VerifierID {
                build: self.config.build_name.clone(),
                developer: self.config.developer_name.clone(),
            },
            raw_evidence: None,
            nonce: None,
            submods,
            extensions,
        };

        debug!(ear =? ear, "Unsigned EAR Token");

        let mut jwt_header = ear::new_jwt_header(&Algorithm::ES256)?;
        jwt_header.jwk = Some(self.pubkey_jwk()?);

        let pkey = PKey::from_ec_key(self.private_key.clone())?;
        let private_key_bytes = pkey.private_key_to_pem_pkcs8()?;

        let signed_ear = ear.sign_jwt_pem_with_header(&jwt_header, &private_key_bytes)?;

        Ok(signed_ear)
    }

    pub async fn set_policy(&self, policy_id: String, policy: String) -> Result<()> {
        self.policy_engine
            .set_policy(&policy_id, &policy, true)
            .await
            .map_err(Error::from)
    }

    pub async fn list_policies(&self) -> Result<Vec<String>> {
        self.policy_engine
            .list_policies()
            .await
            .map_err(Error::from)
    }

    pub async fn get_policy(&self, policy_id: String) -> Result<String> {
        self.policy_engine
            .get_policy(&policy_id)
            .await
            .map_err(Error::from)
    }
}

impl EarAttestationTokenBroker {
    fn pubkey_jwk(&self) -> Result<jwk::Jwk> {
        let chain = self
            .cert_chain
            .as_ref()
            .map(|certs| -> Result<Vec<String>> {
                let mut chain = vec![];
                for cert in certs {
                    let der = cert.to_der()?;
                    chain.push(URL_SAFE_NO_PAD.encode(der));
                }
                Ok(chain)
            })
            .transpose()?;

        let common = jwk::CommonParameters {
            key_algorithm: Some(jwk::KeyAlgorithm::ES256),
            x509_url: self.cert_url.clone(),
            x509_chain: chain,
            ..Default::default()
        };

        let public_key = self.private_key.public_key();
        let group = self.private_key.group();

        let mut ctx = BigNumContext::new()?;
        let mut x = BigNum::new()?;
        let mut y = BigNum::new()?;
        public_key.affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)?;

        let algorithm = jwk::AlgorithmParameters::EllipticCurve(jwk::EllipticCurveKeyParameters {
            key_type: jwk::EllipticCurveKeyType::EC,
            curve: jwk::EllipticCurve::P256,
            x: URL_SAFE_NO_PAD.encode(x.to_vec()),
            y: URL_SAFE_NO_PAD.encode(y.to_vec()),
        });

        let jwk = jwk::Jwk { common, algorithm };

        Ok(jwk)
    }
}

fn generate_ec_keys() -> Result<(EcKey<Private>, Vec<u8>, Vec<u8>)> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec_key = EcKey::generate(&group)?;
    let pkey = PKey::from_ec_key(ec_key.clone())?;

    Ok((
        ec_key,
        pkey.private_key_to_pem_pkcs8()?,
        pkey.public_key_to_pem()?,
    ))
}

/// This function does three things.
///
/// 1) If the input claims include an init_data claim (meaning that
///    the verifier has validated the init_data), add the JSON
///    init_data_claims to the output claims. Do the same thing
///    for the report_data and runtime_data_claims.
///
///    This means that the full init_data and report_data will be
///    available in the token.
///
/// 2) Move all claims from input_claims except the ones mentioned
///    in the previous step into their own Object under the tee name.
///
/// 3) Convert the claims from serde_json Values to RawValues from the
///    EAR crate.
///
pub fn transform_claims(
    mut input_claims: Value,
    init_data_claims: Value,
    mut runtime_data_claims: Value,
    tee: Tee,
    verbose: bool,
) -> Result<BTreeMap<String, RawValue>> {
    let mut output_claims = BTreeMap::new();

    // If the verifier produces an init_data claim (meaning that
    // it has validated the init_data hash), add the JSON init_data_claims,
    // to the claims map. Do the same for the report data.
    //
    // These claims will be flattened and provided to the policy engine.
    // They will also end up in the EAR token as part of the annotated evidence.
    if let Some(claims_map) = input_claims.as_object_mut() {
        if let Some(init_data) = claims_map.remove("init_data") {
            output_claims.insert(
                "init_data".to_string(),
                RawValue::String(init_data.as_str().unwrap().to_string()),
            );

            let transformed_claims: RawValue =
                serde_json::from_str(&serde_json::to_string(&init_data_claims)?)?;
            output_claims.insert("init_data_claims".to_string(), transformed_claims);
        }

        if let Some(report_data) = claims_map.remove("report_data") {
            output_claims.insert(
                "report_data".to_string(),
                RawValue::String(report_data.as_str().unwrap().to_string()),
            );

            // When attesting environments with lots of devices, the additional evidence
            // can create a token that is very large. This can overwhelm the header size
            // limitation of some http servers (including the KBS).
            // If verbose is false, don't include the additional evidence in the token.
            if !verbose {
                runtime_data_claims
                    .as_object_mut()
                    .and_then(|map| map.remove("additional-evidence"));
            }

            let transformed_claims: RawValue =
                serde_json::from_str(&serde_json::to_string(&runtime_data_claims)?)?;

            output_claims.insert("runtime_data_claims".to_string(), transformed_claims);
        }
    }

    let transformed_claims: RawValue =
        serde_json::from_str(&serde_json::to_string(&input_claims)?)?;
    output_claims.insert(to_variant_name(&tee)?.to_string(), transformed_claims);

    Ok(output_claims)
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use jsonwebtoken::DecodingKey;
    use key_value_storage::{KeyValueStorageStructConfig, KeyValueStorageType, SetParameters};
    use serde_json::json;
    use std::io::Write;
    use tempfile::NamedTempFile;

    use crate::{ear_token::TokenSignerConfig, TeeClaims, AS_POLICY_STORAGE_NAMESPACE};

    use super::*;

    #[tokio::test]
    async fn test_issue_ear_ephemeral_key() {
        // use default config with no signer.
        // this will sign the token with an ephemeral key.
        let config = EarTokenConfiguration::default();

        let storage = KeyValueStorageStructConfig::default()
            .to_client_with_namespace(KeyValueStorageType::Memory, AS_POLICY_STORAGE_NAMESPACE)
            .await
            .unwrap();
        storage
            .set(
                "ear_no_rv_policy_cpu.rego",
                include_bytes!("../../tests/coco-as/policy/opa/ear_no_rv_policy_cpu.rego"),
                SetParameters { overwrite: true },
            )
            .await
            .unwrap();
        let broker = EarAttestationTokenBroker::new(config, storage)
            .await
            .unwrap();

        let _token = broker
            .issue(
                vec![TeeClaims {
                    tee: Tee::Sample,
                    tee_class: "cpu".to_string(),
                    claims: json!({"claim": "claim1"}),
                    runtime_data_claims: json!({"runtime_data": "111"}),
                    init_data_claims: json!({"initdata": "111"}),
                }],
                vec!["ear_no_rv_policy".into()],
                None,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_issue_and_validate_ear() {
        let (_pkey, private_key_bytes, public_key_bytes) = generate_ec_keys().unwrap();
        let mut private_key_file = NamedTempFile::new().unwrap();
        private_key_file.write_all(&private_key_bytes).unwrap();

        let signer = TokenSignerConfig {
            key_path: private_key_file.path().to_str().unwrap().to_string(),
            cert_url: None,
            cert_path: None,
        };

        let config = EarTokenConfiguration {
            signer: Some(signer),
            ..Default::default()
        };
        let storage = KeyValueStorageStructConfig::default()
            .to_client_with_namespace(KeyValueStorageType::Memory, AS_POLICY_STORAGE_NAMESPACE)
            .await
            .unwrap();
        storage
            .set(
                "ear_no_rv_policy_cpu.rego",
                include_bytes!("../../tests/coco-as/policy/opa/ear_no_rv_policy_cpu.rego"),
                SetParameters { overwrite: true },
            )
            .await
            .unwrap();
        let broker = EarAttestationTokenBroker::new(config, storage)
            .await
            .unwrap();
        let token = broker
            .issue(
                vec![TeeClaims {
                    tee: Tee::Sample,
                    tee_class: "cpu".to_string(),
                    claims: json!({"claim": "claim1"}),
                    runtime_data_claims: json!({"runtime_data": "111"}),
                    init_data_claims: json!({"initdata": "111"}),
                }],
                vec!["ear_no_rv_policy".into()],
                None,
            )
            .await
            .unwrap();

        let public_key = DecodingKey::from_ec_pem(&public_key_bytes).unwrap();

        let ear = Ear::from_jwt(&token, jsonwebtoken::Algorithm::ES256, &public_key).unwrap();
        ear.validate().unwrap();
    }

    #[rstest::rstest]
    #[case::safe_fallback(json!({}), json!({}), ear::TrustTier::Affirming, 3)]
    #[case::approved_configuration(
        json!({}),
        json!({
            "snp_smt_enabled": true,
            "snp_tsme_enabled": false,
            "snp_guest_abi_major": 1,
            "snp_guest_abi_minor": 0,
            "snp_single_socket": false,
            "snp_smt_allowed": true
        }),
        ear::TrustTier::Affirming,
        2
    )]
    #[case::configuration_mismatch_falls_back(
        json!({}),
        json!({"snp_smt_enabled": false}),
        ear::TrustTier::Affirming,
        3
    )]
    #[case::unapproved_measurement(
        json!({"measurement": "ff".repeat(48)}),
        json!({}),
        ear::TrustTier::Contraindicated,
        3
    )]
    #[case::unapproved_tcb(
        json!({"reported_tcb_microcode": 255}),
        json!({}),
        ear::TrustTier::Contraindicated,
        3
    )]
    #[case::missing_measurement_allowlist(
        json!({}),
        json!({"snp_launch_measurement": null}),
        ear::TrustTier::Contraindicated,
        3
    )]
    #[case::missing_tcb_allowlist(
        json!({}),
        json!({"snp_microcode": null}),
        ear::TrustTier::Contraindicated,
        3
    )]
    #[case::debug_allowed(
        json!({"policy_debug_allowed": true}),
        json!({}),
        ear::TrustTier::Contraindicated,
        96
    )]
    #[case::migration_allowed(
        json!({"policy_migrate_ma": true}),
        json!({}),
        ear::TrustTier::Contraindicated,
        96
    )]
    #[case::missing_debug_claim(
        json!({"policy_debug_allowed": null}),
        json!({}),
        ear::TrustTier::Contraindicated,
        96
    )]
    #[case::missing_migration_claim(
        json!({"policy_migrate_ma": null}),
        json!({}),
        ear::TrustTier::Contraindicated,
        96
    )]
    #[tokio::test]
    async fn test_issue_snp_configuration_fallback(
        #[case] claim_overrides: Value,
        #[case] reference_overrides: Value,
        #[case] expected_status: ear::TrustTier,
        #[case] expected_configuration: i8,
    ) {
        use crate::rvps::{builtin::BuiltinRvps, RvpsApi};

        let mut claims = json!({
            "measurement": "aa".repeat(48),
            "reported_tcb_bootloader": 10,
            "reported_tcb_microcode": 84,
            "reported_tcb_snp": 24,
            "reported_tcb_tee": 0,
            "policy_debug_allowed": false,
            "policy_migrate_ma": false,
            "platform_smt_enabled": true,
            "platform_tsme_enabled": false,
            "policy_abi_major": 1,
            "policy_abi_minor": 0,
            "policy_single_socket": false,
            "policy_smt_allowed": true
        });
        let mut references = json!({
            "snp_launch_measurement": ["aa".repeat(48)],
            "snp_bootloader": [10],
            "snp_microcode": [84],
            "snp_snp_svn": [24],
            "snp_tee_svn": [0]
        });
        for (values, overrides) in [
            (&mut claims, claim_overrides),
            (&mut references, reference_overrides),
        ] {
            for (key, value) in overrides.as_object().unwrap() {
                if value.is_null() {
                    values.as_object_mut().unwrap().remove(key);
                } else {
                    values[key] = value.clone();
                }
            }
        }
        let storage_config = KeyValueStorageStructConfig::default();
        let mut rvps = BuiltinRvps::new(None, KeyValueStorageType::Memory, &storage_config)
            .await
            .unwrap();
        let registration = json!({
            "type": "sample",
            "payload": base64::engine::general_purpose::STANDARD.encode(references.to_string())
        });
        rvps.verify_and_extract(&registration.to_string())
            .await
            .unwrap();
        let storage = storage_config
            .to_client_with_namespace(KeyValueStorageType::Memory, AS_POLICY_STORAGE_NAMESPACE)
            .await
            .unwrap();
        let broker = EarAttestationTokenBroker::new(EarTokenConfiguration::default(), storage)
            .await
            .unwrap();
        let token = broker
            .issue(
                vec![TeeClaims {
                    tee: Tee::Snp,
                    tee_class: "cpu".into(),
                    claims,
                    init_data_claims: json!({}),
                    runtime_data_claims: json!({}),
                }],
                vec!["default".into()],
                Some(std::sync::Arc::new(tokio::sync::Mutex::new(rvps))),
            )
            .await
            .unwrap();
        let public_key = broker.private_key.public_key_to_pem().unwrap();
        let public_key = DecodingKey::from_ec_pem(&public_key).unwrap();
        let ear = Ear::from_jwt(&token, jsonwebtoken::Algorithm::ES256, &public_key).unwrap();
        ear.validate().unwrap();
        let cpu = &ear.submods["cpu0"];
        assert_eq!(cpu.status, expected_status);
        assert_eq!(
            cpu.trust_vector.configuration.value(),
            expected_configuration
        );
    }

    #[test]
    fn test_transform_claims() {
        let json = json!({
            "ccel": {
                "kernel": "5b7aa6572f649714ff00b6a2b9170516a068fd1a0ba72aa8de27574131d454e6396d3bfa1727d9baf421618a942977fa",
                "kernel_parameters": {
                    "console": "hvc0",
                    "root": "/dev/vda1",
                    "rw": ""
                }
            },
            "quote": {
                "header":{
                    "version": "0400",
                    "att_key_type": "0200",
                    "tee_type": "81000000",
                    "reserved": "00000000",
                    "vendor_id": "939a7233f79c4ca9940a0db3957f0607",
                    "user_data": "d099bfec0a477aa85a605dceabf2b10800000000"
                },
                "body":{
                    "mr_config_id": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "mr_owner": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "mr_owner_config": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "mr_td": "705ee9381b8633a9fbe532b52345e8433343d2868959f57889d84ca377c395b689cac1599ccea1b7d420483a9ce5f031",
                    "mrsigner_seam": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429",
                    "seam_attributes": "0000000000000000",
                    "td_attributes": "0100001000000000",
                    "mr_seam": "2fd279c16164a93dd5bf373d834328d46008c2b693af9ebb865b08b2ced320c9a89b4869a9fab60fbe9d0c5a5363c656",
                    "tcb_svn": "03000500000000000000000000000000",
                    "xfam": "e742060000000000"
                }
            },
            "report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429",
            "init_data": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        });

        let init_data_claims = Value::String("".to_string());
        let runtime_data_claims = Value::String("".to_string());
        let transformed_claims =
            transform_claims(json, init_data_claims, runtime_data_claims, Tee::Tdx, true)
                .expect("flatten failed");

        let expected_claims = json!({
            "tdx": {
                "ccel": {
                    "kernel": "5b7aa6572f649714ff00b6a2b9170516a068fd1a0ba72aa8de27574131d454e6396d3bfa1727d9baf421618a942977fa",
                    "kernel_parameters": {
                        "console": "hvc0",
                        "root": "/dev/vda1",
                        "rw": ""
                    }
                },
                "quote": {
                    "header":{
                        "version": "0400",
                        "att_key_type": "0200",
                        "tee_type": "81000000",
                        "reserved": "00000000",
                        "vendor_id": "939a7233f79c4ca9940a0db3957f0607",
                        "user_data": "d099bfec0a477aa85a605dceabf2b10800000000"
                    },
                    "body":{
                        "mr_config_id": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                        "mr_owner": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                        "mr_owner_config": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                        "mr_td": "705ee9381b8633a9fbe532b52345e8433343d2868959f57889d84ca377c395b689cac1599ccea1b7d420483a9ce5f031",
                        "mrsigner_seam": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                        "report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429",
                        "seam_attributes": "0000000000000000",
                        "td_attributes": "0100001000000000",
                        "mr_seam": "2fd279c16164a93dd5bf373d834328d46008c2b693af9ebb865b08b2ced320c9a89b4869a9fab60fbe9d0c5a5363c656",
                        "tcb_svn": "03000500000000000000000000000000",
                        "xfam": "e742060000000000"
                    }
                }
            },
            "report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429",
            "init_data": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "runtime_data_claims": "",
            "init_data_claims": ""
        });

        assert_json_eq!(expected_claims, transformed_claims);
    }

    #[tokio::test]
    async fn test_shipped_default_policy_overwrites_persisted_stale_copy() {
        let config = EarTokenConfiguration::default();
        let storage = KeyValueStorageStructConfig::default()
            .to_client_with_namespace(KeyValueStorageType::Memory, AS_POLICY_STORAGE_NAMESPACE)
            .await
            .unwrap();
        // Simulate an upgraded deployment whose persistent policy storage
        // still carries the pre-upgrade default under the shipped name.
        storage
            .set(
                "default_cpu.rego",
                b"# stale pre-upgrade policy",
                SetParameters { overwrite: true },
            )
            .await
            .unwrap();
        let broker = EarAttestationTokenBroker::new(config, storage)
            .await
            .unwrap();
        assert_eq!(
            broker.get_policy("default_cpu".to_string()).await.unwrap(),
            include_str!("ear_default_policy_cpu.rego"),
            "the shipped default must replace a persisted copy at startup"
        );
    }

    /// A storage double whose writes always fail, counting every attempted
    /// `set` — root-proof replacement for the chmod'd LocalFs repro (Devin
    /// review on #17: mode bits do not stop root): what matters to the broker
    /// contract is that no write is ATTEMPTED for identical content and that
    /// a needed write's failure fails startup.
    struct FailingWritesStorage {
        inner: key_value_storage::memory::MemoryKeyValueStorage,
        set_attempts: std::sync::atomic::AtomicUsize,
    }

    impl FailingWritesStorage {
        async fn preloaded(shipped: bool) -> Self {
            use key_value_storage::KeyValueStorage as _;
            let inner = key_value_storage::memory::MemoryKeyValueStorage::default();
            let shipped_policies = [
                (
                    "default_cpu.rego",
                    include_str!("ear_default_policy_cpu.rego"),
                ),
                (
                    "default_gpu.rego",
                    include_str!("ear_default_policy_gpu.rego"),
                ),
                (
                    "default_switch.rego",
                    include_str!("ear_default_policy_switch.rego"),
                ),
                (
                    "default_ppcie.rego",
                    include_str!("ear_default_policy_ppcie.rego"),
                ),
            ];
            for (index, (key, policy)) in shipped_policies.iter().enumerate() {
                let content = if shipped || index != 0 {
                    (*policy).to_string()
                } else {
                    "# stale pre-upgrade policy".to_string()
                };
                inner
                    .set(key, content.as_bytes(), SetParameters { overwrite: true })
                    .await
                    .unwrap();
            }
            Self {
                inner,
                set_attempts: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn set_attempts(&self) -> usize {
            self.set_attempts.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl key_value_storage::KeyValueStorage for FailingWritesStorage {
        async fn set(
            &self,
            key: &str,
            _value: &[u8],
            _parameters: SetParameters,
        ) -> std::result::Result<
            key_value_storage::SetResult,
            key_value_storage::KeyValueStorageError,
        > {
            self.set_attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // Report what a read-only backend reports: the write is refused.
            Err(key_value_storage::KeyValueStorageError::SetKeyFailed {
                source: anyhow::anyhow!("simulated read-only store"),
                key: key.to_string(),
            })
        }

        async fn update_if_present(
            &self,
            key: &str,
            value: &[u8],
        ) -> std::result::Result<
            key_value_storage::UpdateResult,
            key_value_storage::KeyValueStorageError,
        > {
            self.inner.update_if_present(key, value).await
        }

        async fn list(
            &self,
        ) -> std::result::Result<Vec<String>, key_value_storage::KeyValueStorageError> {
            self.inner.list().await
        }

        async fn get(
            &self,
            key: &str,
        ) -> std::result::Result<Option<Vec<u8>>, key_value_storage::KeyValueStorageError> {
            self.inner.get(key).await
        }

        async fn delete(
            &self,
            key: &str,
        ) -> std::result::Result<Option<Vec<u8>>, key_value_storage::KeyValueStorageError> {
            self.inner.delete(key).await
        }

        async fn delete_if_present(
            &self,
            key: &str,
        ) -> std::result::Result<
            key_value_storage::DeleteResult,
            key_value_storage::KeyValueStorageError,
        > {
            self.inner.delete_if_present(key).await
        }
    }

    #[tokio::test]
    async fn test_shipped_default_policy_identical_preload_needs_no_write() {
        let storage = std::sync::Arc::new(FailingWritesStorage::preloaded(true).await);
        EarAttestationTokenBroker::new(EarTokenConfiguration::default(), storage.clone())
            .await
            .expect(
                "an identical read-only preload must start cleanly — registration must not \
                 rewrite identical content (Devin review on #17)",
            );
        assert_eq!(
            storage.set_attempts(),
            0,
            "no write may be attempted for identical preloaded content"
        );
    }

    #[tokio::test]
    async fn test_shipped_default_policy_stale_preload_on_read_only_storage_fails_startup() {
        let result = EarAttestationTokenBroker::new(
            EarTokenConfiguration::default(),
            std::sync::Arc::new(FailingWritesStorage::preloaded(false).await),
        )
        .await;
        assert!(
            result.is_err(),
            "a stale policy on read-only storage must fail startup, never be silently \
             served (Devin review on #17)"
        );
    }

    #[test]
    fn test_shipped_policy_locking_defaults_to_fail_closed() {
        // The evaluation-time authority gate is config-driven and FAILS
        // CLOSED by default: deployments that legitimately reconfigure
        // appraisal under a shipped id (the upstream KBS integration
        // harness shape) must explicitly opt out.
        assert!(EarTokenConfiguration::default().lock_shipped_default_policies);
        let unlocked: EarTokenConfiguration =
            serde_json::from_str(r#"{"lock_shipped_default_policies": false}"#).unwrap();
        assert!(!unlocked.lock_shipped_default_policies);
    }

    #[tokio::test]
    async fn test_diverged_shipped_policy_is_restored_not_evaluated() {
        // Devin review on #17, round 3: a policy mutated in storage AFTER
        // construction (e.g. through the policy API) must not be served to
        // evaluation — the authority re-assert restores the shipped bytes.
        let storage = KeyValueStorageStructConfig::default()
            .to_client_with_namespace(KeyValueStorageType::Memory, AS_POLICY_STORAGE_NAMESPACE)
            .await
            .unwrap();
        let broker =
            EarAttestationTokenBroker::new(EarTokenConfiguration::default(), storage.clone())
                .await
                .unwrap();
        // Simulate the post-construction mutation under a shipped id.
        broker
            .set_policy(
                "default_cpu".to_string(),
                "# mutated after startup".to_string(),
            )
            .await
            .unwrap();
        assert_ne!(
            broker.get_policy("default_cpu".to_string()).await.unwrap(),
            include_str!("ear_default_policy_cpu.rego"),
            "fixture: the mutation landed"
        );
        EarAttestationTokenBroker::ensure_shipped_policies_authoritative(&broker.policy_engine)
            .await
            .unwrap();
        assert_eq!(
            broker.get_policy("default_cpu".to_string()).await.unwrap(),
            include_str!("ear_default_policy_cpu.rego"),
            "the evaluation-time re-assert must restore the shipped content before any EAR \
             is appraised with diverged rules"
        );
    }
}
