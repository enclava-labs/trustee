// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0

//! Interfaces for cryptography.

pub mod key;
pub(crate) mod sig;
pub mod sm;

use crate::{
    certs::{Algorithm, Usage},
    crypto::key::ecc,
    Body,
};
use openssl::hash;
use openssl_sys::EC_KEY;
use std::io::{Error, ErrorKind, Result};

#[derive(Debug)]
pub struct Signature {
    pub id: Option<[u8; 16]>,
    pub sig: Vec<u8>,
    pub algo: Option<Algorithm>,
    pub usage: Usage,
}

/// Represents a private key.
pub struct PrivateKey<U> {
    pub id: Option<[u8; 16]>,
    pub key: *mut EC_KEY,
    pub hash: hash::MessageDigest,
    pub usage: U,
}

#[derive(Debug)]
pub struct PublicKey {
    pub id: Option<[u8; 16]>,
    pub key: ecc::PubKey,
    pub algo: Option<Algorithm>,
    pub usage: Usage,
}

impl PublicKey {
    pub fn verify(
        &self,
        msg: &impl codicon::Encoder<Body, Error = Error>,
        uid: &[u8],
        sig: &Signature,
    ) -> Result<()> {
        let usage_valid = sig.usage == self.usage;
        let algo_valid = sig.algo.is_none() || sig.algo == self.algo;
        let id_valid = sig.id.is_none() || sig.id == self.id;
        if !usage_valid || !algo_valid || !id_valid {
            return Err(ErrorKind::InvalidInput.into());
        }

        let mut buf: Vec<u8> = Vec::new();
        msg.encode(&mut buf, Body)?;
        sm::SM2::verify(self.key, &sig.sig, &Vec::from(uid), &buf).map(|ok| {
            // SM2 verify will return Ok(true) if the signature
            // is verified and Ok(false) if not. This patches the result
            // to return Err if SM2 returns Ok(false).
            if ok {
                Ok(())
            } else {
                Err(ErrorKind::NotFound.into())
            }
        })?
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        sm::SM2::encrypt(&data, self.key)
    }
}
